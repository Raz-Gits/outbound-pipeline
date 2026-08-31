"""SSRF guard.

Two layers:

1. ``is_safe_url(url)`` — quick pre-check. Resolves the hostname and rejects
   private / loopback / link-local / metadata-service / multicast / reserved
   IPs. Cheap and side-effect-free, but on its own is vulnerable to a
   DNS-rebinding race: the IP that passes the check is not necessarily the
   IP httpx connects to milliseconds later.

2. ``safe_get(client, url, ...)`` — full safe fetch. Resolves once, validates,
   then *pins* the resolved addrinfo in a thread-local map and monkey-patches
   ``socket.getaddrinfo`` for the duration of the call so any subsequent DNS
   lookup for that hostname returns the pinned, validated tuples. Eliminates
   the TOCTOU window. Also enforces a max response body size (defends against
   gigabyte-sitemap memory-exhaustion attacks).

Use ``safe_get`` for any new outbound call against a URL derived from
attacker-controlled input (scraped domains, sitemap <loc> URLs, JSON-LD
fields, etc). ``is_safe_url`` is retained for legacy callsites and as a
no-op wrapper; new code should prefer ``safe_get``.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from contextlib import contextmanager
from typing import Iterator
from urllib.parse import urljoin, urlparse

import httpx

# Default max response body. Defends any page/sitemap fetch from a malicious
# site serving a multi-GB document.
DEFAULT_MAX_BYTES = 10_000_000  # 10 MiB

# Preserve the original resolver so the patched version can delegate to it
# for unpinned hostnames.
_real_getaddrinfo = socket.getaddrinfo
_pin_local = threading.local()
_patch_installed = False
_patch_lock = threading.Lock()


def _is_safe_ip(ip_str: str) -> tuple[bool, str]:
    """Return (ok, reason) for one resolved IP literal.

    Rejects:
      - RFC1918 private (10/8, 172.16/12, 192.168/16) and IPv6 fc00::/7
      - Loopback (127/8, ::1)
      - Link-local (169.254/16, fe80::/10) — covers cloud metadata 169.254.169.254
      - Multicast / reserved / unspecified
      - 0.0.0.0/8 (current network — some kernels route to localhost)
      - 100.64.0.0/10 (CGNAT)
      - IPv4-mapped IPv6 like ``::ffff:127.0.0.1`` (would otherwise slip past
        the bare ``is_loopback`` check on the IPv6 form)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"bad ip: {ip_str}"
    # Unwrap IPv4-mapped IPv6 so we evaluate the underlying v4 address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    ):
        return False, f"blocked ip {ip_str}"
    # Extra IPv4 ranges not covered by ipaddress.is_private:
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.IPv4Network("0.0.0.0/8"):
            return False, f"blocked ip {ip_str} (0.0.0.0/8)"
        if ip in ipaddress.IPv4Network("100.64.0.0/10"):
            return False, f"blocked ip {ip_str} (CGNAT)"
    return True, "ok"


def is_safe_url(url: str) -> tuple[bool, str]:
    """Quick pre-check. See module docstring re: TOCTOU — prefer ``safe_get``."""
    if not url or not isinstance(url, str):
        return False, "empty url"
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"parse error: {e}"
    if parsed.scheme not in ("http", "https"):
        return False, f"scheme not http/https: {parsed.scheme!r}"
    host = parsed.hostname
    if not host:
        return False, "no hostname"
    try:
        infos = _real_getaddrinfo(host, None)
    except socket.gaierror as e:
        return False, f"dns error: {e}"
    except UnicodeError as e:
        # IDNA encoding rejects empty labels ('foo..com'), labels > 63 chars,
        # and a few other edge cases. socket.gaierror does not subsume this;
        # without it the cascade dies hard on a single malformed domain.
        return False, f"idna error: {e}"
    for info in infos:
        ip_str = info[4][0]
        ok, reason = _is_safe_ip(ip_str)
        if not ok:
            return False, f"{reason} for host {host}"
    return True, "ok"


def validate_redirect(response: httpx.Response) -> None:
    """httpx response hook: abort the chain if a 3xx Location points to an unsafe host."""
    if 300 <= response.status_code < 400:
        loc = response.headers.get("location")
        if not loc:
            return
        target = urljoin(str(response.request.url), loc)
        ok, reason = is_safe_url(target)
        if not ok:
            raise httpx.HTTPError(f"unsafe redirect: {target} ({reason})")


# ---------------------------------------------------------------------------
# DNS pinning — thread-local override of socket.getaddrinfo
# ---------------------------------------------------------------------------
_UNSET = object()


def _patched_getaddrinfo(host, port=None, family=0, type=0, proto=0, flags=0):
    """Return pinned addrinfo for `host` if present, swapping in the caller's port.

    The cache is built once per safe_get() with whatever port was in the URL
    (often None → sockaddr port=0). Callers like httpcore re-resolve with the
    actual destination port (443/80); we have to splice the requested port
    into the cached sockaddr so they can connect to the right port.

    Honors family/type/proto filters the same way the real getaddrinfo does
    (0 = wildcard). Without this, ``socket.create_connection`` — which calls
    ``getaddrinfo(host, port, 0, SOCK_STREAM)`` — would receive UDP entries
    and try to ``connect()`` a SOCK_DGRAM socket, failing with EINVAL.
    """
    pinned = getattr(_pin_local, "pinned", None)
    if pinned is not None and host in pinned:
        try:
            port_int = int(port) if port is not None else 0
        except (TypeError, ValueError):
            port_int = 0
        out = []
        for fam, socktype, prot, canonname, sockaddr in pinned[host]:
            if family and fam != family:
                continue
            if type and socktype != type:
                continue
            if proto and prot != proto:
                continue
            # sockaddr: (ip, port) for AF_INET; (ip, port, flow, scope) for AF_INET6
            new_sockaddr = (sockaddr[0], port_int) + sockaddr[2:]
            out.append((fam, socktype, prot, canonname, new_sockaddr))
        if out:
            return out
        # If filters left nothing (unusual), fall through to a real lookup so
        # we don't synthesize an empty result and break the caller.
    return _real_getaddrinfo(host, port, family, type, proto, flags)


def _ensure_patch_installed() -> None:
    global _patch_installed
    if _patch_installed:
        return
    with _patch_lock:
        if _patch_installed:
            return
        socket.getaddrinfo = _patched_getaddrinfo
        _patch_installed = True


@contextmanager
def _pin_dns(host: str, addrinfo: list) -> Iterator[None]:
    """Pin DNS resolution of `host` to `addrinfo` for the duration of the block.

    Thread-local: only affects lookups on the current thread.
    """
    _ensure_patch_installed()
    pinned = getattr(_pin_local, "pinned", None)
    if pinned is None:
        pinned = {}
        _pin_local.pinned = pinned
    prev = pinned.get(host, _UNSET)
    pinned[host] = addrinfo
    try:
        yield
    finally:
        if prev is _UNSET:
            pinned.pop(host, None)
        else:
            pinned[host] = prev


def _resolve_and_validate(host: str, port: int | None) -> list:
    """Resolve `host` and return the addrinfo list IFF every IP passes the
    safe-IP check. Raises ``httpx.HTTPError`` otherwise.
    """
    try:
        infos = _real_getaddrinfo(host, port)
    except socket.gaierror as e:
        raise httpx.ConnectError(f"DNS error for {host}: {e}") from e
    except UnicodeError as e:
        raise httpx.InvalidURL(f"IDNA error for {host}: {e}") from e
    if not infos:
        raise httpx.ConnectError(f"DNS returned no addresses for {host}")
    for info in infos:
        ip_str = info[4][0]
        ok, reason = _is_safe_ip(ip_str)
        if not ok:
            raise httpx.HTTPError(
                f"SSRF: refusing {host} ({reason})"
            )
    return infos


def safe_get(
    client: httpx.Client,
    url: str,
    *,
    timeout: float | httpx.Timeout = 12.0,
    max_bytes: int = DEFAULT_MAX_BYTES,
    **kwargs,
) -> httpx.Response:
    """SSRF-safe + size-bounded GET.

    1. Parses the URL, resolves the hostname once.
    2. Validates every resolved IP via ``_is_safe_ip``.
    3. Pins the addrinfo in a thread-local map and monkey-patches
       ``socket.getaddrinfo`` so httpx's own DNS lookup returns the same
       pre-validated IPs (closes the TOCTOU rebind window).
    4. Streams the response body, aborting if it exceeds ``max_bytes``.

    Returns a fully-buffered ``httpx.Response`` — ``.text`` / ``.content`` /
    ``.headers`` / ``.status_code`` / ``.url`` are all populated, exactly as
    if the caller had used ``client.get(url)``. Drop-in replacement.

    Raises ``httpx.HTTPError`` on SSRF, ``httpx.ConnectError`` on DNS failure,
    or oversized-response. Other transport errors propagate from httpx as
    usual — callers that catch ``httpx.HTTPError`` already handle this.
    """
    if not url or not isinstance(url, str):
        raise httpx.InvalidURL("empty url")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise httpx.InvalidURL(f"scheme not http/https: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise httpx.InvalidURL(f"no host in {url!r}")

    addrinfo = _resolve_and_validate(host, parsed.port)

    with _pin_dns(host, addrinfo):
        with client.stream("GET", url, timeout=timeout, **kwargs) as r:
            cl = r.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > max_bytes:
                raise httpx.HTTPError(
                    f"response too large: content-length={cl} > {max_bytes}"
                )
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise httpx.HTTPError(
                        f"response body exceeded {max_bytes} bytes"
                    )
            # Promote to a non-streamed Response so .text / .content work.
            r._content = bytes(buf)
            return r

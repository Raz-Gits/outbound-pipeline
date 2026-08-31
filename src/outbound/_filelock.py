"""Portable interprocess file lock.

fcntl exists only on Unix and msvcrt only on Windows, so anything that wants
an interprocess lock and a cross-platform repo has to carry this shim once.
Used by the paid-spend ledger: two concurrent processes (an overlapping
manual run + a cron, say) must not lose a credit increment between a read
and a write, or the monthly cap silently under-counts real money.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:  # Unix
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

except ImportError:  # Windows
    import msvcrt

    def _lock(fd: int) -> None:
        # Lock one byte at offset 0; blocks until acquired.
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


@contextmanager
def file_lock(path: str | Path) -> Iterator[None]:
    """Hold an exclusive interprocess lock for the duration of the block.

    `path` is the lock file itself (created if absent), not the file being
    protected — keeping them separate means the protected file can be
    atomically replaced (os.replace) while the lock is held.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        # The lock byte must exist before msvcrt can lock it.
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        _lock(fd)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)

# agent/storage.py
from __future__ import annotations

import asyncio
import hashlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncIterator


class StorageError(Exception):
    """Raised for any storage backend failure."""


class FileNotFoundError(StorageError):
    """Raised when a requested file/hash doesn't exist in the backend."""


class StorageBackend(ABC):
    """
    Abstract interface for any storage backend — local disk, Google Drive,
    Dropbox, etc. All methods are async so implementations can use non-
    blocking I/O (httpx for cloud APIs, aiofiles for local disk).

    The agent's downloader and p2p_server never import LocalStorage or
    DriveAdapter directly — they only ever hold a StorageBackend reference.
    Swapping the backend (local dev → cloud prod) requires changing one
    line in config/startup, not touching any transfer logic.
    """

    @abstractmethod
    async def exists(self, file_hash: str) -> bool:
        """Return True if a file with this sha256 hash is available."""

    @abstractmethod
    async def get_size(self, file_hash: str) -> int:
        """Return total byte size of the file. Raises FileNotFoundError."""

    @abstractmethod
    async def read_range(
        self,
        file_hash: str,
        start: int,
        end: int,
    ) -> AsyncIterator[bytes]:
        """
        Yield chunks of bytes covering [start, end] inclusive.
        Must not buffer the full range in memory — implementations stream
        from their source in whatever chunk size is natural for the backend
        (network response buffer, filesystem block, etc).
        Raises FileNotFoundError if the file doesn't exist.
        Raises StorageError for backend failures.
        """

    @abstractmethod
    async def write_stream(
        self,
        file_hash: str,
        stream: AsyncIterator[bytes],
    ) -> int:
        """
        Consume an async byte stream and persist it under file_hash.
        Returns total bytes written. Does not verify the hash — callers
        that care about integrity should check after write_stream returns.
        Raises StorageError on failure.
        """

    @abstractmethod
    async def preallocate(self, file_hash: str, size: int) -> None:
        """
        Create (or truncate) the destination file for file_hash to exactly
        `size` bytes upfront, before any chunk writes happen. This exists
        so multiple concurrent writers (different peers, each supplying a
        different byte range of the same file — see downloader.py's
        sub-chunked fetch) can safely seek+write to their own offsets of
        an already-correctly-sized file, without racing each other to
        create it first or needing to know the final size at write time.
        Raises StorageError on failure.
        """

    @abstractmethod
    async def write_chunk_at(self, file_hash: str, offset: int, data: bytes) -> None:
        """
        Write `data` at byte offset `offset` within file_hash's destination
        file. Requires preallocate() to have been called first for this
        file_hash. This is what makes bounded-memory, sub-chunked, multi-
        peer transfer possible — each verified sub-chunk is written
        directly to its correct position and immediately discarded from
        memory, rather than accumulated in Python and written all at once
        at the end (which would defeat the whole point of sub-chunking).
        Raises StorageError on failure.
        """

    @abstractmethod
    async def delete(self, file_hash: str) -> None:
        """Remove the file. No-op if it doesn't exist."""

    @abstractmethod
    async def list_files(self) -> list[str]:
        """Return all file hashes currently held by this backend."""


class LocalStorage(StorageBackend):
    """
    Dev/demo implementation — stores files on local disk under a root
    directory, named by their sha256 hash. Async reads use a thread pool
    via asyncio.to_thread so we don't block the event loop on disk I/O.
    This is replaced by DriveAdapter in production.
    """

    # Read in 64 KB chunks — large enough to amortise syscall overhead,
    # small enough that memory pressure stays flat regardless of file size.
    CHUNK_SIZE = 64 * 1024

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, file_hash: str) -> Path:
        return self.root / file_hash

    async def exists(self, file_hash: str) -> bool:
        return await asyncio.to_thread(self._path_for(file_hash).exists)

    async def get_size(self, file_hash: str) -> int:
        path = self._path_for(file_hash)
        try:
            return await asyncio.to_thread(lambda: path.stat().st_size)
        except OSError as e:
            raise FileNotFoundError(f"file {file_hash!r} not found: {e}") from e

    async def read_range(
        self,
        file_hash: str,
        start: int,
        end: int,
    ) -> AsyncIterator[bytes]:
        return self._read_range_impl(file_hash, start, end)

    async def _read_range_impl(
        self,
        file_hash: str,
        start: int,
        end: int,
    ) -> AsyncIterator[bytes]:
        path = self._path_for(file_hash)
        if not await asyncio.to_thread(path.exists):
            raise FileNotFoundError(f"file {file_hash!r} not found")

        total = end - start + 1
        offset = start
        remaining = total

        def _open_and_seek():
            f = path.open("rb")
            f.seek(offset)
            return f

        fh = await asyncio.to_thread(_open_and_seek)
        try:
            while remaining > 0:
                to_read = min(self.CHUNK_SIZE, remaining)
                chunk = await asyncio.to_thread(fh.read, to_read)
                if not chunk:
                    break
                yield chunk
                remaining -= len(chunk)
        finally:
            await asyncio.to_thread(fh.close)

    async def write_stream(
        self,
        file_hash: str,
        stream: AsyncIterator[bytes],
    ) -> int:
        path = self._path_for(file_hash)
        total = 0

        fh = await asyncio.to_thread(lambda: path.open("wb"))
        try:
            async for chunk in stream:
                await asyncio.to_thread(fh.write, chunk)
                total += len(chunk)
        except Exception as e:
            await asyncio.to_thread(fh.close)
            await asyncio.to_thread(path.unlink, True)
            raise StorageError(f"write failed for {file_hash!r}: {e}") from e

        await asyncio.to_thread(fh.close)
        return total

    async def preallocate(self, file_hash: str, size: int) -> None:
        """
        Create a sparse file of exactly `size` bytes. On most filesystems
        this doesn't actually allocate `size` bytes of real disk space
        upfront — seeking past the end and truncating creates "holes"
        that only become real allocated blocks once something is
        actually written there, which is exactly what write_chunk_at
        does as each sub-chunk arrives.
        """
        path = self._path_for(file_hash)

        def _create():
            with path.open("wb") as f:
                f.truncate(size)

        try:
            await asyncio.to_thread(_create)
        except OSError as e:
            raise StorageError(f"preallocate failed for {file_hash!r}: {e}") from e

    async def write_chunk_at(self, file_hash: str, offset: int, data: bytes) -> None:
        """
        Seek to `offset` in the (already preallocated) file and write
        `data`. Multiple concurrent callers writing to DIFFERENT offsets
        of the same file is safe on a normal filesystem — each open file
        handle here is independent and seeks to its own position before
        writing, so peers fetching different byte ranges concurrently
        don't interfere with each other.
        """
        path = self._path_for(file_hash)

        def _write():
            with path.open("r+b") as f:
                f.seek(offset)
                f.write(data)

        try:
            await asyncio.to_thread(_write)
        except OSError as e:
            raise StorageError(
                f"write_chunk_at failed for {file_hash!r} at offset {offset}: {e}"
            ) from e

    async def delete(self, file_hash: str) -> None:
        path = self._path_for(file_hash)
        await asyncio.to_thread(path.unlink, True)  # missing_ok=True

    async def list_files(self) -> list[str]:
        def _list():
            return [p.name for p in self.root.iterdir() if p.is_file()]
        return await asyncio.to_thread(_list)


async def compute_sha256(stream: AsyncIterator[bytes]) -> str:
    """Utility — hash an async byte stream without buffering it entirely.
    Used by tests and by p2p_server to verify chunk integrity."""
    h = hashlib.sha256()
    async for chunk in stream:
        h.update(chunk)
    return h.hexdigest()
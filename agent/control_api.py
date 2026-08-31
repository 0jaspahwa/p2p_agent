# agent/control_api.py
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agent.downloader import Downloader, DownloadError, DownloadResult

logger = logging.getLogger(__name__)


class DownloadStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class TrackedDownload:
    download_id: str
    file_hash: str
    status: DownloadStatus = DownloadStatus.PENDING
    result: DownloadResult | None = None
    error: str | None = None
    started_at: float = field(default_factory=time.time)
    # Live progress, updated via downloader.py's on_size_known/on_bytes
    # callbacks while status == RUNNING. bytes_downloaded is a running
    # total across however many peers are concurrently supplying chunks;
    # total_bytes_expected is None until the file size is actually known
    # (right after the initial FileInfoRequest, before any chunk fetch
    # starts) — receive.py falls back to showing just bytes-so-far with
    # no denominator until this is set.
    bytes_downloaded: int = 0
    total_bytes_expected: int | None = None
    file_name: str | None = None


class DownloadRequest(BaseModel):
    file_hash: str


def _storage_root(storage) -> str | None:
    """
    Best-effort lookup of a storage backend's on-disk root, without
    assuming a concrete class. Mirrors the same getattr fallback chain
    p2p_server.py uses for .meta lookups — kept in sync deliberately so
    both sides agree on where a given StorageBackend actually lives on
    disk. Returns None for a backend with no local filesystem root at
    all (e.g. a future HTTP/cloud-backed StorageBackend), in which case
    storage_path is simply omitted from the API response.
    """
    return getattr(storage, "root", getattr(storage, "_root", getattr(storage, "base_path", None)))


def build_control_api(downloader: Downloader) -> FastAPI:
    """
    Local-only control API for a running agent — lets an external CLI or
    tool ask this specific, already-running agent to download a file,
    using its own already-bound iroh Endpoint, its own identity, and its
    own trust relationships.

    SECURITY: this must NEVER be reachable from anywhere but the local
    machine. main.py hardcodes the bind host to 127.0.0.1 regardless of
    config for exactly this reason — anyone who can reach this API can
    make YOUR agent initiate downloads under YOUR identity, consuming
    YOUR trust relationships. There is no auth on top of "can you reach
    this port" by design, because the only thing that's supposed to be
    able to reach it is you, on your own machine.

    Downloads run as background asyncio tasks and are polled by ID
    rather than blocking the POST response — a large file could take
    longer than any reasonable HTTP client timeout if we waited inline.
    """
    app = FastAPI(title="p2p-agent control API", version="0.1.0")
    downloads: dict[str, TrackedDownload] = {}
    storage_root = _storage_root(downloader.storage)

    async def _run_download(tracked: TrackedDownload) -> None:
        tracked.status = DownloadStatus.RUNNING

        def _on_size_known(size: int, name: str | None) -> None:
            tracked.total_bytes_expected = size
            tracked.file_name = name

        def _on_bytes(n: int) -> None:
            tracked.bytes_downloaded += n

        try:
            result = await downloader.download(
                tracked.file_hash,
                on_size_known=_on_size_known,
                on_bytes=_on_bytes,
            )
            tracked.result = result
            tracked.status = DownloadStatus.COMPLETE
            logger.info("control API: download %s complete", tracked.download_id)
        except DownloadError as e:
            tracked.error = str(e)
            tracked.status = DownloadStatus.FAILED
            logger.warning(
                "control API: download %s failed: %s", tracked.download_id, e
            )

    @app.post("/downloads")
    async def start_download(req: DownloadRequest) -> dict:
        download_id = str(uuid.uuid4())
        tracked = TrackedDownload(download_id=download_id, file_hash=req.file_hash)
        downloads[download_id] = tracked
        asyncio.create_task(_run_download(tracked))
        logger.info(
            "control API: started download %s for %s",
            download_id, req.file_hash[:12],
        )
        return {"download_id": download_id, "status": tracked.status.value}

    @app.get("/downloads/{download_id}")
    async def get_download(download_id: str) -> dict:
        tracked = downloads.get(download_id)
        if tracked is None:
            raise HTTPException(status_code=404, detail="unknown download_id")

        response: dict = {
            "download_id": tracked.download_id,
            "file_hash": tracked.file_hash,
            "status": tracked.status.value,
            "bytes_downloaded": tracked.bytes_downloaded,
            "total_bytes_expected": tracked.total_bytes_expected,
        }
        if tracked.result is not None:
            response["result"] = {
                "total_bytes": tracked.result.total_bytes,
                "verified": tracked.result.verified,
                "file_name": tracked.result.file_name,
                "peers_used": tracked.result.peers_used,
            }
            # storage_path is what devtools/receive.py copies from to
            # produce a friendly-named export in the caller's cwd. Must
            # be ABSOLUTE: receive.py runs as a separate process from
            # this agent, so a relative storage.root (e.g. "./downloads"
            # in settings.yaml) would resolve against receive.py's own
            # working directory, not the agent's — silently pointing at
            # the wrong location (or nothing at all) if the two
            # processes were launched from different folders.
            if storage_root is not None:
                response["result"]["storage_path"] = os.path.abspath(
                    os.path.join(str(storage_root), tracked.result.file_hash)
                )
        if tracked.error is not None:
            response["error"] = tracked.error
        return response

    @app.get("/downloads")
    async def list_downloads() -> dict:
        return {
            "downloads": [
                {
                    "download_id": d.download_id,
                    "file_hash": d.file_hash,
                    "status": d.status.value,
                }
                for d in downloads.values()
            ]
        }

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    return app
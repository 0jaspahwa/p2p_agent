# agent/tracker_client.py
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


class TrackerError(Exception):
    """Raised when the tracker returns an error or is unreachable."""


@dataclass
class PeerAddress:

    agent_id: str


class TrackerClient:
 

    DEFAULT_TIMEOUT = 5.0      # seconds — tracker requests should be fast
    MAX_RETRIES = 2

    def __init__(
        self,
        tracker_url: str,
        agent_id: str,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        # Strip trailing slash so we can always do f"{base}/path" cleanly
        self.tracker_url = tracker_url.rstrip("/")
        self.agent_id = agent_id
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "TrackerClient":
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    # --- public API ---

    async def register(self, file_hashes: list[str]) -> int:
        """
        Announce this agent as a seeder for the given files.
        Returns the number of file entries registered.
        Call periodically as a keepalive — re-registration resets TTL.

        No host/port here anymore — under iroh, the tracker's job
        simplifies to just "who has this file" (a set of agent_ids).
        Actually REACHING a peer (NAT traversal, relay fallback, direct
        connection) is iroh's job, not the tracker's, once it has the
        agent_id to derive an EndpointId from.
        """
        resp = await self._post(
            "/register",
            {
                "agent_id": self.agent_id,
                "file_hashes": file_hashes,
            },
        )
        return resp["registered"]

    async def get_peers(self, file_hash: str) -> list[PeerAddress]:
        """
        Return all live peers currently seeding a file.
        Excludes this agent itself — no point connecting to yourself.
        """
        resp = await self._get(f"/peers/{file_hash}")
        return [
            PeerAddress(agent_id=p["agent_id"])
            for p in resp["peers"]
            if p["agent_id"] != self.agent_id
        ]

    async def unregister(self, file_hashes: list[str] | None = None) -> None:

        try:
            await self._post(
                "/unregister",
                {
                    "agent_id": self.agent_id,
                    "file_hashes": file_hashes,
                },
            )
        except TrackerError as e:
            logger.warning("unregister failed (best-effort): %s", e)

    async def keepalive(self, file_hashes: list[str]) -> None:
        """Re-register to reset TTL. Call every ~peer_ttl/2 seconds."""
        await self.register(file_hashes)

    # --- internals ---

    async def _get(self, path: str) -> dict:
        url = f"{self.tracker_url}{path}"
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                resp = await self._client.get(url)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as e:
                raise TrackerError(
                    f"tracker returned {e.response.status_code} for GET {path}"
                ) from e
            except httpx.TransportError as e:
                if attempt == self.MAX_RETRIES:
                    raise TrackerError(
                        f"tracker unreachable after {self.MAX_RETRIES} attempts: {e}"
                    ) from e
                wait = 0.5 * attempt
                logger.warning(
                    "tracker GET %s failed (attempt %d/%d), retrying in %.1fs",
                    path, attempt, self.MAX_RETRIES, wait,
                )
                await asyncio.sleep(wait)
        raise TrackerError("unreachable")  # satisfies type checker

    async def _post(self, path: str, body: dict) -> dict:
        url = f"{self.tracker_url}{path}"
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                resp = await self._client.post(url, json=body)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as e:
                raise TrackerError(
                    f"tracker returned {e.response.status_code} for POST {path}"
                ) from e
            except httpx.TransportError as e:
                if attempt == self.MAX_RETRIES:
                    raise TrackerError(
                        f"tracker unreachable after {self.MAX_RETRIES} attempts: {e}"
                    ) from e
                wait = 0.5 * attempt
                logger.warning(
                    "tracker POST %s failed (attempt %d/%d), retrying in %.1fs",
                    path, attempt, self.MAX_RETRIES, wait,
                )
                await asyncio.sleep(wait)
        raise TrackerError("unreachable")
# agent/gateway_client.py
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

import httpx

from agent.identity import AgentIdentity

logger = logging.getLogger(__name__)


class GatewayError(Exception):
    """Raised when the gateway rejects a request or is unreachable."""


@dataclass
class PathResult:
    """Result of a /path trust lookup."""
    verified: bool
    degrees_of_separation: int | None = None
    trust_chain: list[str] | None = None
    message: str = ""


class GatewayClient:
    """
    Talks to the Cryptographic Trust Gateway (Node/Express) on behalf of
    this agent's identity. This is the Python equivalent of what
    persistent_node.py / execute_revoke.py do manually — register,
    vouch, revoke — plus the /path lookup those scripts don't need.

    Every signed payload here MUST byte-for-byte match what
    authMiddleware.js reconstructs server-side:
      - vouch:  {issuer_id, subject_id, issued_at, expires_at}
      - revoke: {issuer_id, subject_id, action: "REVOKE", timestamp}
    Both as JSON with no extra whitespace (separators=(",", ":")) and in
    this exact key order — dict insertion order is preserved by Python's
    json.dumps, so the dict literal order below IS the wire order.

    identity.sign() only signs raw bytes; it has no knowledge of these
    shapes, so this class is responsible for building the canonical
    payload before signing — same division of responsibility as
    AgentIdentity's own docstring describes for trust.py.
    """

    def __init__(
        self,
        gateway_url: str,
        identity: AgentIdentity,
        timeout: float = 10.0,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.identity = identity
        self._client = httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "GatewayClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    # -------------------------------------------------------------------
    # Register
    # -------------------------------------------------------------------

    async def register(self) -> None:
        """
        Register this agent's identity with the gateway. Idempotent from
        the caller's perspective — if the gateway returns 409 (agent
        already exists), that's treated as success, not an error, since
        main.py may call this on every startup.
        """
        payload = {
            "agent_id": self.identity.agent_id,
            "public_key": self.identity.agent_id,  # base64 raw pubkey — same value
        }
        try:
            resp = await self._client.post(f"{self.gateway_url}/register", json=payload)
        except httpx.TransportError as e:
            raise GatewayError(f"gateway unreachable during register: {e}") from e

        if resp.status_code == 201:
            logger.info("registered with gateway: %s", self.identity.agent_id[:16])
            return
        if resp.status_code == 409:
            logger.debug("already registered with gateway: %s", self.identity.agent_id[:16])
            return

        raise GatewayError(f"register failed: HTTP {resp.status_code} — {resp.text}")

    # -------------------------------------------------------------------
    # Vouch
    # -------------------------------------------------------------------

    async def vouch_for(self, subject_id: str, ttl_seconds: float = 365 * 24 * 3600) -> None:
        """
        Issue a signed vouch for subject_id, valid for ttl_seconds
        (default 1 year). expires_at is in SECONDS since epoch — the
        gateway's checkTrustPath multiplies by 1000 to compare against
        Neo4j's timestamp(), which is milliseconds. Do not pre-multiply
        here.
        """
        now = time.time()
        payload = {
            "issuer_id": self.identity.agent_id,
            "subject_id": subject_id,
            "issued_at": int(now),
            "expires_at": int(now + ttl_seconds),
        }
        signature = self._sign_canonical(payload)

        try:
            resp = await self._client.post(
                f"{self.gateway_url}/vouch",
                json={**payload, "signature": signature},
            )
        except httpx.TransportError as e:
            raise GatewayError(f"gateway unreachable during vouch: {e}") from e

        if resp.status_code != 201:
            raise GatewayError(f"vouch failed: HTTP {resp.status_code} — {resp.text}")

        logger.info(
            "vouched for %s (expires in %ds)", subject_id[:16], int(ttl_seconds)
        )

    # -------------------------------------------------------------------
    # Revoke
    # -------------------------------------------------------------------

    async def revoke(self, subject_id: str) -> None:
        """Revoke a previously issued vouch for subject_id."""
        payload = {
            "issuer_id": self.identity.agent_id,
            "subject_id": subject_id,
            "action": "REVOKE",
            "timestamp": int(time.time()),
        }
        signature = self._sign_canonical(payload)

        try:
            resp = await self._client.post(
                f"{self.gateway_url}/revoke",
                json={**payload, "signature": signature},
            )
        except httpx.TransportError as e:
            raise GatewayError(f"gateway unreachable during revoke: {e}") from e

        if resp.status_code != 200:
            raise GatewayError(f"revoke failed: HTTP {resp.status_code} — {resp.text}")

        logger.info("revoked vouch for %s", subject_id[:16])

    # -------------------------------------------------------------------
    # Path lookup
    # -------------------------------------------------------------------

    async def check_path(self, start_id: str, end_id: str) -> PathResult:
        """
        Ask the gateway whether a trust path exists start_id -> end_id.
        This is a read — no signature required, matches GET /path being
        unauthenticated in server.js.
        """
        try:
            resp = await self._client.get(
                f"{self.gateway_url}/path",
                params={"start_id": start_id, "end_id": end_id},
            )
        except httpx.TransportError as e:
            raise GatewayError(f"gateway unreachable during path check: {e}") from e

        if resp.status_code == 404:
            body = resp.json()
            return PathResult(verified=False, message=body.get("message", ""))

        if resp.status_code != 200:
            raise GatewayError(f"path check failed: HTTP {resp.status_code} — {resp.text}")

        body = resp.json()
        return PathResult(
            verified=body.get("verified", False),
            degrees_of_separation=body.get("degrees_of_separation"),
            trust_chain=body.get("trust_chain"),
        )

    # -------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------

    def _sign_canonical(self, payload: dict) -> str:
        """
        Build the exact canonical JSON string authMiddleware.js will
        reconstruct, and sign it. separators=(",", ":") strips whitespace
        to match JSON.stringify's default compact output.
        """
        canonical = json.dumps(payload, separators=(",", ":"))
        return self.identity.sign(canonical.encode("utf-8"))

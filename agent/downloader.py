# agent/downloader.py
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Callable

import iroh


from agent.identity import AgentIdentity
from agent.gateway_client import GatewayClient, GatewayError
from agent.messages import (
    ChunkHeader,
    ErrorMessage,
    FileRequestAck,
    FileRequestReject,
    TransferComplete,
    FileRequest,
    HandshakeRequest,
    HandshakeResponse,
    FileInfoResponse,
    FileInfoRequest
)
from agent.serializer import decode, decode_as, DeserializationError, encode
from agent.storage import StorageBackend
from agent.tracker_client import PeerAddress, TrackerClient
from agent.trust import TrustEngine
from agent.p2p_server import ALPN, MAX_READ_BYTES, SUB_CHUNK_SIZE

logger = logging.getLogger(__name__)


class DownloadError(Exception):
    """Raised when a download fails unrecoverably."""


class PeerRejectedError(DownloadError):
    """Raised when a peer rejects our request (trust, rate limit, etc)."""


class ChecksumMismatchError(DownloadError):
    """
    Raised when a peer's delivered bytes don't match the checksum THEY
    claimed in ChunkHeader. Distinct from other DownloadErrors because
    this is a strong, unambiguous signal of bad behavior rather than
    ordinary network flakiness — TCP already guarantees byte-level
    integrity in transit, so a mismatch here means the peer's own code
    sent bytes inconsistent with its own claimed checksum. This is what
    triggers automatic revocation in Downloader.download().
    """

# ---------------------------------------------------------------------------
# Range assignment — unchanged, transport-agnostic
# ---------------------------------------------------------------------------

def _split_ranges(
    file_size: int,
    peer_count: int,
    min_chunk: int = 256 * 1024,   # 256 KB minimum per peer
) -> list[tuple[int, int]]:

    if file_size == 0:
        return []
    actual_peers = min(peer_count, max(1, file_size // min_chunk))
    chunk = file_size // actual_peers
    ranges = []
    for i in range(actual_peers):
        start = i * chunk
        end = (start + chunk - 1) if i < actual_peers - 1 else file_size - 1
        ranges.append((start, end))
    return ranges


def _peer_endpoint_addr(peer: PeerAddress) -> "iroh.EndpointAddr":
    """
    peer.agent_id is base64 of the raw Ed25519 public key — the exact
    same bytes an iroh EndpointId is derived from. No host/port needed;
    that's the whole point of iroh. relay_url=None / addresses=[] means
    we rely entirely on iroh's discovery (preset_n0) to find this peer,
    same as proven in the standalone iroh_prototype scripts.
    """
    raw = base64.b64decode(peer.agent_id)
    endpoint_id = iroh.EndpointId.from_bytes(raw)
    return iroh.EndpointAddr(id=endpoint_id, relay_url=None, addresses=[])


# ---------------------------------------------------------------------------
# Per-peer download task
# ---------------------------------------------------------------------------

@dataclass
class ChunkResult:

    peer: PeerAddress
    range_start: int
    range_end: int
    bytes_written: int


async def _handshake_peer(
    endpoint: "iroh.Endpoint",
    peer: PeerAddress,
    identity: AgentIdentity,
    gateway: GatewayClient,
    max_depth: int,
) -> bool:
    """
    Perform trust handshake with a peer over iroh. Returns True if the
    peer accepted us AND the gateway confirms an actual, unexpired vouch
    path exists from us to them — False otherwise, including if the
    gateway is unreachable (fail closed, no local fallback).
    """
    import base64 as b64
    import os

    nonce = b64.b64encode(os.urandom(32)).decode("ascii")

    req = HandshakeRequest(
        sender_id=identity.agent_id,
        trust_chain=[],
        nonce=nonce,
    )

    try:
        peer_addr = _peer_endpoint_addr(peer)
        connection = await endpoint.connect(peer_addr, ALPN)
    except Exception as e:
        logger.warning("handshake connect error with %s: %s", peer.agent_id[:12], e)
        return False

    try:
        bi = await connection.open_bi()
        send_stream = bi.send()
        recv_stream = bi.recv()

        await send_stream.write_all(encode(req))
        await send_stream.finish()

        raw = await recv_stream.read_to_end(MAX_READ_BYTES)
    except Exception as e:
        logger.warning("handshake stream error with %s: %s", peer.agent_id[:12], e)
        return False

    try:
        msg = decode(raw)
    except DeserializationError as e:
        logger.warning("bad handshake response from %s: %s", peer.agent_id[:12], e)
        return False

    if isinstance(msg, ErrorMessage):
        logger.info(
            "handshake rejected by %s: %s — %s", peer.agent_id[:12], msg.code, msg.detail
        )
        return False

    if not isinstance(msg, HandshakeResponse):
        logger.warning(
            "unexpected handshake response type from %s: %s",
            peer.agent_id[:12], type(msg).__name__,
        )
        return False


    if not AgentIdentity.verify(msg.sender_id, nonce.encode("utf-8"), msg.nonce_signature):
        logger.warning(
            "nonce signature verification failed for %s", peer.agent_id[:12]
        )
        return False

    # Confirm the responder is actually who we intended to dial.
    if msg.sender_id != peer.agent_id:
        logger.warning(
            "handshake identity mismatch: dialed %s, got response signed by %s",
            peer.agent_id[:12], msg.sender_id[:12],
        )
        return False

    # Authorization: gateway's vouch graph. Fail closed on any gateway error.
    try:
        result = await gateway.check_path(identity.agent_id, msg.sender_id)
    except GatewayError as e:
        logger.warning(
            "gateway unreachable during trust check for %s — rejecting: %s",
            peer.agent_id[:12], e,
        )
        return False

    if not result.verified:
        logger.info(
            "no trust path to %s: %s", peer.agent_id[:12], result.message
        )
        return False

    if result.degrees_of_separation is not None and result.degrees_of_separation > max_depth:
        logger.info(
            "trust path to %s exists but exceeds max_depth (%d > %d)",
            peer.agent_id[:12], result.degrees_of_separation, max_depth,
        )
        return False

    logger.debug(
        "handshake succeeded with %s (degrees=%s)",
        peer.agent_id[:12], result.degrees_of_separation,
    )
    return True


async def _fetch_file_info(
    endpoint: "iroh.Endpoint",
    peer: PeerAddress,
    identity: AgentIdentity,
    file_hash: str,
) -> tuple[int, str | None]:
    """Asks a single peer for the file size."""
    req = FileInfoRequest(file_hash=file_hash, sender_id=identity.agent_id)

    try:
        peer_addr = _peer_endpoint_addr(peer)
        connection = await endpoint.connect(peer_addr, ALPN)
        bi = await connection.open_bi()
        send_stream = bi.send()
        recv_stream = bi.recv()

        await send_stream.write_all(encode(req))
        await send_stream.finish()

        raw = await recv_stream.read_to_end(MAX_READ_BYTES)
    except Exception as e:
        raise DownloadError(f"file info transport error with {peer.agent_id[:12]}: {e}") from e

    try:
        msg = decode(raw)
    except DeserializationError as e:
        raise DownloadError(f"bad metadata response from {peer.agent_id[:12]}: {e}") from e

    if isinstance(msg, ErrorMessage):
        raise DownloadError(f"peer {peer.agent_id[:12]} error: {msg.code} - {msg.detail}")

    if not isinstance(msg, FileInfoResponse):
        raise DownloadError(f"unexpected response type: {type(msg).__name__}")

    return msg.file_size, msg.file_name


async def _fetch_one_subchunk(
    connection: "iroh.Connection",
    identity: AgentIdentity,
    file_hash: str,
    range_start: int,
    range_end: int,
    peer: PeerAddress,
) -> bytes:

    req = FileRequest(
        file_hash=file_hash,
        range_start=range_start,
        range_end=range_end,
        sender_id=identity.agent_id,
    )

    try:
        bi = await connection.open_bi()
        send_stream = bi.send()
        recv_stream = bi.recv()

        await send_stream.write_all(encode(req))
        await send_stream.finish()

        content = await recv_stream.read_to_end(MAX_READ_BYTES)
    except Exception as e:
        raise DownloadError(f"transfer transport error with {peer.agent_id[:12]}: {e}") from e

    # The server may respond with a single self-contained rejection/error
    # message instead of the 4-frame Ack/Header/bytes/Complete sequence.
    try:
        single_msg = decode(content)
    except DeserializationError:
        single_msg = None

    if isinstance(single_msg, FileRequestReject):
        raise PeerRejectedError(
            f"peer {peer.agent_id[:12]} rejected: {single_msg.reason} — {single_msg.detail}"
        )
    if isinstance(single_msg, ErrorMessage):
        raise DownloadError(
            f"peer {peer.agent_id[:12]} returned error: {single_msg.code} — {single_msg.detail}"
        )

    try:
        idx = content.index(b"\n")
        ack = decode_as(content[:idx], FileRequestAck)
        assert isinstance(ack, FileRequestAck)

        idx2 = content.index(b"\n", idx + 1)
        header = decode_as(content[idx + 1:idx2], ChunkHeader)
        assert isinstance(header, ChunkHeader)

        raw_start = idx2 + 1
        raw_bytes = content[raw_start:raw_start + header.chunk_size]

        complete_start = raw_start + header.chunk_size + 1
        complete = decode_as(content[complete_start:], TransferComplete)
        assert isinstance(complete, TransferComplete)

    except (ValueError, DeserializationError) as e:
        raise DownloadError(f"bad frame from {peer.agent_id[:12]}: {e}") from e

    actual_checksum = hashlib.sha256(raw_bytes).hexdigest()
    if actual_checksum != header.checksum:
        raise ChecksumMismatchError(
            f"checksum mismatch from {peer.agent_id[:12]} "
            f"(sub-chunk {range_start}-{range_end}): "
            f"expected {header.checksum}, got {actual_checksum}"
        )

    return raw_bytes


async def _fetch_chunk(
    endpoint: "iroh.Endpoint",
    peer: PeerAddress,
    identity: AgentIdentity,
    storage: StorageBackend,
    file_hash: str,
    range_start: int,
    range_end: int,
    on_bytes: "Callable[[int], None] | None" = None,
) -> ChunkResult:

    try:
        peer_addr = _peer_endpoint_addr(peer)
        connection = await endpoint.connect(peer_addr, ALPN)
    except Exception as e:
        raise DownloadError(f"connect error with {peer.agent_id[:12]}: {e}") from e

    total_written = 0
    pos = range_start
    while pos <= range_end:
        sub_end = min(pos + SUB_CHUNK_SIZE - 1, range_end)
        data = await _fetch_one_subchunk(
            connection, identity, file_hash, pos, sub_end, peer
        )
        await storage.write_chunk_at(file_hash, pos, data)
        total_written += len(data)
        if on_bytes is not None:
            on_bytes(len(data))
        pos = sub_end + 1

    return ChunkResult(
        peer=peer,
        range_start=range_start,
        range_end=range_end,
        bytes_written=total_written,
    )



# Downloader
@dataclass
class DownloadResult:
    file_hash: str
    total_bytes: int
    peers_used: list[str]       # agent_ids
    verified: bool              # final sha256 matched expected hash
    file_name: str | None = None


class Downloader:

    def __init__(
        self,
        identity: AgentIdentity,
        trust_engine: TrustEngine,
        tracker: TrackerClient,
        storage: StorageBackend,
        gateway: GatewayClient,
        endpoint: "iroh.Endpoint",
        max_peers: int = 4,
        timeout: float = 30.0,
        auto_revoke_threshold: int = 1,
    ):
        self.identity = identity
        self.trust_engine = trust_engine
        self.tracker = tracker
        self.storage = storage
        self.gateway = gateway
        self.endpoint = endpoint
        self.max_peers = max_peers
        self.timeout = timeout
        self.auto_revoke_threshold = auto_revoke_threshold
        self._checksum_failures: dict[str, int] = {}

    async def _handle_checksum_failure(self, peer_agent_id: str) -> None:
        """
        Record a checksum mismatch from peer_agent_id and revoke our vouch
        for them via the gateway once auto_revoke_threshold is reached.
        Best-effort: a gateway failure here is logged, not raised.
        """
        count = self._checksum_failures.get(peer_agent_id, 0) + 1
        self._checksum_failures[peer_agent_id] = count
        logger.warning(
            "checksum mismatch #%d from %s", count, peer_agent_id[:12]
        )

        if count < self.auto_revoke_threshold:
            return

        logger.warning(
            "peer %s hit auto-revoke threshold (%d) — revoking vouch",
            peer_agent_id[:12], self.auto_revoke_threshold,
        )
        try:
            await self.gateway.revoke(peer_agent_id)
        except GatewayError as e:
            logger.error(
                "auto-revoke failed for %s (gateway unreachable?): %s",
                peer_agent_id[:12], e,
            )

    async def download(
        self,
        file_hash: str,
        on_size_known: "Callable[[int, str | None], None] | None" = None,
        on_bytes: "Callable[[int], None] | None" = None,
    ) -> DownloadResult:
        candidates = await self.tracker.get_peers(file_hash)
        if not candidates:
            raise DownloadError(f"no peers found for {file_hash[:12]}")
        return await self.download_from_peers(
            file_hash, candidates, on_size_known=on_size_known, on_bytes=on_bytes
        )

    async def download_from_peers(
        self,
        file_hash: str,
        candidates: list[PeerAddress],
        on_size_known: "Callable[[int, str | None], None] | None" = None,
        on_bytes: "Callable[[int], None] | None" = None,
    ) -> DownloadResult:

        candidates = candidates[: self.max_peers]

        trusted_peers = await self._handshake_all(candidates)
        if not trusted_peers:
            raise DownloadError("no peers passed trust handshake")

        # Fetch the file size (and name, if known) from the first trusted
        # peer — the caller no longer needs to supply it manually.
        logger.info("fetching file size for %s...", file_hash[:12])
        try:
            file_size, file_name = await _fetch_file_info(
                self.endpoint, trusted_peers[0], self.identity, file_hash
            )
        except DownloadError as e:
            raise DownloadError(f"failed to determine file size: {e}")

        logger.info("starting download of %s (%d bytes)", file_hash[:12], file_size)
        if on_size_known is not None:
            on_size_known(file_size, file_name)


        await self.storage.preallocate(file_hash, file_size)

        try:
            ranges = _split_ranges(file_size, len(trusted_peers))
            peer_range_pairs = list(zip(trusted_peers, ranges))

            tasks = [
                _fetch_chunk(
                    self.endpoint, peer, self.identity, self.storage, file_hash, start, end,
                    on_bytes=on_bytes,
                )
                for peer, (start, end) in peer_range_pairs
            ]
            results: list[ChunkResult | BaseException] = await asyncio.gather(
                *tasks, return_exceptions=True
            )

            chunks: list[ChunkResult] = []
            for i, result in enumerate(results):
                if isinstance(result, BaseException):
                    peer = peer_range_pairs[i][0]
                    logger.warning(
                        "chunk %d failed from %s: %s",
                        i, peer.agent_id[:12], result,
                    )
                    if isinstance(result, ChecksumMismatchError):
                        await self._handle_checksum_failure(peer.agent_id)
                else:
                    chunks.append(result)

            if not chunks:
                raise DownloadError("all chunk fetches failed")

            chunks.sort(key=lambda c: c.range_start)
            expected_start = 0
            for chunk in chunks:
                if chunk.range_start != expected_start:
                    raise DownloadError(
                        f"gap in coverage: expected range starting at {expected_start}, "
                        f"got {chunk.range_start}"
                    )
                expected_start = chunk.range_end + 1

            if expected_start != file_size:
                raise DownloadError(
                    f"incomplete download: got {expected_start}/{file_size} bytes"
                )
        except DownloadError:
            logger.error(
                "download of %s failed before completion — removing partial file",
                file_hash[:12],
            )
            await self.storage.delete(file_hash)
            raise

        total_bytes = sum(c.bytes_written for c in chunks)


        byte_stream = await self.storage.read_range(file_hash, 0, file_size - 1)
        final_hash = hashlib.sha256()
        async for chunk in byte_stream:
            final_hash.update(chunk)
        verified = final_hash.hexdigest() == file_hash

        if not verified:
            logger.error("final hash mismatch for %s — discarding", file_hash[:12])
            await self.storage.delete(file_hash)
            raise DownloadError(f"final hash verification failed for {file_hash}")

        peers_used = [c.peer.agent_id for c in chunks]
        logger.info(
            "download complete: %s (%d bytes, %d peers, verified=%s)",
            file_hash[:12], total_bytes, len(peers_used), verified,
        )
        return DownloadResult(
            file_hash=file_hash,
            total_bytes=total_bytes,
            peers_used=peers_used,
            verified=verified,
            file_name=file_name,
        )

    async def _handshake_all(
        self,
        candidates: list[PeerAddress],
    ) -> list[PeerAddress]:
        """Handshake with all candidates concurrently, return only trusted ones."""
        tasks = [
            _handshake_peer(self.endpoint, peer, self.identity, self.gateway, self.trust_engine.max_depth)
            for peer in candidates
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        trusted = []
        for peer, result in zip(candidates, results):
            if result is True:
                trusted.append(peer)
            else:
                logger.debug(
                    "peer %s failed handshake: %s", peer.agent_id[:12], result
                )
        return trusted
# agent/p2p_server.py
from __future__ import annotations

import asyncio
import hashlib
import logging
import os

import iroh

from agent.identity import AgentIdentity
from agent.gateway_client import GatewayClient, GatewayError
from agent.messages import (
    ChunkHeader,
    ErrorMessage,
    FileRequest,
    FileRequestAck,
    FileRequestReject,
    HandshakeRequest,
    HandshakeResponse,
    TransferComplete,
    FileInfoRequest,
    FileInfoResponse
)
from agent.serializer import DeserializationError, decode, encode
from agent.storage import StorageBackend
from agent.trust import TrustEngine

logger = logging.getLogger(__name__)

# ALPN identifies this specific protocol to iroh — analogous to a URL path
# prefix, but negotiated at the QUIC connection level rather than per-request.
# Bump the version suffix if the wire format ever changes incompatibly.
ALPN = b"p2p-agent/handshake-transfer/1"

# Size of each individually-requested, individually-verified sub-chunk
# within a peer's assigned range. This is what actually bounds memory use
# during a transfer — a 2GB file is fetched as ~250 separate 8MB
# round-trips instead of one giant request, so neither side ever holds
# more than one sub-chunk in memory at once. MAX_READ_BYTES above is now
# effectively a safety ceiling, not the normal operating size.
SUB_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB

# Read limit for a SINGLE stream's response. With sub-chunking (below),
# normal responses are ~SUB_CHUNK_SIZE, never the whole file — so this
# is now a defensive ceiling against a malicious/misbehaving peer sending
# an oversized single response, not something that needs headroom for a
# whole multi-GB file the way it did before sub-chunking existed.
MAX_READ_BYTES = 64 * 1024 * 1024  # 64 MB — generous headroom over an 8MB sub-chunk


class P2PServer:
    """
    Seeding side of the agent — iroh transport version.

    Replaces the previous FastAPI app (POST /handshake, POST /transfer)
    with a persistent iroh Endpoint that accepts connections by identity
    (EndpointId) rather than by host:port. Routing that used to happen via
    URL path now happens via serializer.decode()'s existing type-field
    dispatch — every incoming stream's first frame tells us whether it's
    a HandshakeRequest or a FileRequest.

    All trust-checking logic (gateway.check_path, fail-closed on
    GatewayError, max_depth enforcement) is unchanged from the HTTP
    version — only the transport carrying the request/response bytes
    is different.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        trust_engine: TrustEngine,
        storage: StorageBackend,
        gateway: GatewayClient,
    ):
        self.identity = identity
        self.trust_engine = trust_engine
        self.storage = storage
        self.gateway = gateway
        self.dev_trust_all = os.environ.get("P2P_TRUST_ALL", "").lower() == "true"
        if self.dev_trust_all:
            logger.warning(
                "P2P_TRUST_ALL is enabled — ALL trust checks are bypassed. "
                "This must never be set in a non-dev environment."
            )
        self.endpoint: iroh.Endpoint | None = None
        self._accept_task: asyncio.Task | None = None
        self._connection_tasks: set[asyncio.Task] = set()

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def start(self) -> None:
        """
        Bind an iroh Endpoint using this agent's EXISTING Ed25519 identity
        (same key the gateway already knows about — see
        identity.raw_private_bytes()), and start accepting connections.
        """
        options = iroh.EndpointOptions(
            secret_key=self.identity.raw_private_bytes(),
            alpns=[ALPN],
            preset=iroh.preset_n0(),
        )
        self.endpoint = await iroh.Endpoint.bind(options)
        logger.info(
            "iroh endpoint bound: %s", self.endpoint.id().fmt_short()
        )
        self._accept_task = asyncio.create_task(self._accept_loop())

    async def stop(self) -> None:
        """Stop accepting new connections and close the endpoint cleanly."""
        if self._accept_task:
            self._accept_task.cancel()
        for task in list(self._connection_tasks):
            task.cancel()
        if self.endpoint:
            await self.endpoint.close()
        logger.info("iroh endpoint closed")

    # -----------------------------------------------------------------------
    # Accept loop
    # -----------------------------------------------------------------------

    async def _accept_loop(self) -> None:
        assert self.endpoint is not None
        while True:
            incoming = await self.endpoint.accept_next()
            if incoming is None:
                logger.info("endpoint closed, accept loop exiting")
                return
            task = asyncio.create_task(self._handle_connection(incoming))
            self._connection_tasks.add(task)
            task.add_done_callback(self._connection_tasks.discard)

    async def _handle_connection(self, incoming: "iroh.Incoming") -> None:
        try:
            accepting = await incoming.accept()
            connection = await accepting.connect()
        except Exception as e:
            logger.warning("failed to establish incoming connection: %s", e)
            return

        peer_short = connection.remote_id().fmt_short()
        logger.debug("connection established from %s", peer_short)

        # A single connection may carry multiple requests over its
        # lifetime (e.g. a handshake, then one or more transfer requests).
        # Accept streams on this connection until it closes.
        while True:
            try:
                bi = await connection.accept_bi()
            except Exception:
                logger.debug("connection from %s closed", peer_short)
                return
            asyncio.create_task(self._handle_stream(bi))

    # -----------------------------------------------------------------------
    # Per-stream dispatch — replaces the old FastAPI route handlers
    # -----------------------------------------------------------------------

    async def _handle_stream(self, bi: "iroh.BiStream") -> None:
        recv_stream = bi.recv()
        send_stream = bi.send()

        try:
            raw = await recv_stream.read_to_end(MAX_READ_BYTES)
        except Exception as e:
            logger.warning("failed to read incoming stream: %s", e)
            return

        try:
            msg = decode(raw)
        except DeserializationError as e:
            await self._send_message(
                send_stream, ErrorMessage(code="bad_request", detail=str(e))
            )
            return

        if isinstance(msg, HandshakeRequest):
            await self._handle_handshake(msg, send_stream)
        elif isinstance(msg, FileRequest):
            await self._handle_transfer(msg, send_stream)
        elif isinstance(msg, FileInfoRequest):
            await self._handle_file_info(msg, send_stream)
        else:
            await self._send_message(
                send_stream,
                ErrorMessage(
                    code="bad_request",
                    detail=f"unexpected message type: {type(msg).__name__}",
                ),
            )

    async def _send_message(self, send_stream: "iroh.SendStream", message) -> None:
        await send_stream.write_all(encode(message))
        await send_stream.finish()

    # -----------------------------------------------------------------------
    # Handshake — same trust-check logic as the HTTP version, unchanged
    # -----------------------------------------------------------------------

    async def _handle_handshake(
        self, msg: HandshakeRequest, send_stream: "iroh.SendStream"
    ) -> None:
        if not self.dev_trust_all:
            try:
                result = await self.gateway.check_path(self.identity.agent_id, msg.sender_id)
            except GatewayError as e:
                logger.warning(
                    "gateway unreachable during handshake trust check for %s — rejecting: %s",
                    msg.sender_id[:12], e,
                )
                await self._send_message(
                    send_stream,
                    ErrorMessage(code="no_trust_path", detail="trust gateway unreachable"),
                )
                return

            if not result.verified:
                logger.info(
                    "handshake rejected for %s: %s", msg.sender_id[:12], result.message
                )
                await self._send_message(
                    send_stream,
                    ErrorMessage(code="no_trust_path", detail=result.message),
                )
                return

            if (
                result.degrees_of_separation is not None
                and result.degrees_of_separation > self.trust_engine.max_depth
            ):
                logger.info(
                    "handshake rejected for %s: path exists but exceeds max_depth (%d > %d)",
                    msg.sender_id[:12], result.degrees_of_separation, self.trust_engine.max_depth,
                )
                await self._send_message(
                    send_stream,
                    ErrorMessage(
                        code="no_trust_path",
                        detail=(
                            f"trust path exceeds max depth "
                            f"({result.degrees_of_separation} > {self.trust_engine.max_depth})"
                        ),
                    ),
                )
                return

        nonce_sig = self.identity.sign(msg.nonce.encode("utf-8"))
        response = HandshakeResponse(
            sender_id=self.identity.agent_id,
            nonce_signature=nonce_sig,
        )
        await self._send_message(send_stream, response)

    async def _handle_file_info(
        self, msg: FileInfoRequest, send_stream: "iroh.SendStream"
    ) -> None:
        # Same trust gate as _handle_handshake/_handle_transfer — file
        # metadata (size, name) is not public just because a peer knows
        # the hash. Without this, anyone reachable could probe any hash
        # for its size/filename with zero trust relationship at all,
        # which is a real information leak even though it doesn't hand
        # over file bytes.
        if not self.dev_trust_all:
            try:
                result = await self.gateway.check_path(self.identity.agent_id, msg.sender_id)
            except GatewayError as e:
                logger.warning(
                    "gateway unreachable during file-info trust check for %s — rejecting: %s",
                    msg.sender_id[:12], e,
                )
                await self._send_message(
                    send_stream,
                    ErrorMessage(code="no_trust_path", detail="trust gateway unreachable"),
                )
                return

            if not result.verified:
                await self._send_message(
                    send_stream,
                    ErrorMessage(
                        code="no_trust_path",
                        detail=result.message or "no trust path to sender",
                    ),
                )
                return

            if (
                result.degrees_of_separation is not None
                and result.degrees_of_separation > self.trust_engine.max_depth
            ):
                await self._send_message(
                    send_stream,
                    ErrorMessage(
                        code="no_trust_path",
                        detail=(
                            f"trust path exceeds max depth "
                            f"({result.degrees_of_separation} > {self.trust_engine.max_depth})"
                        ),
                    ),
                )
                return

        if not await self.storage.exists(msg.file_hash):
            await self._send_message(
                send_stream,
                ErrorMessage(code="file_not_found", detail=f"no file with hash {msg.file_hash}")
            )
            return

        file_size = await self.storage.get_size(msg.file_hash)
        
        import os
        import json
        file_name = None
        
        try:
            storage_root = getattr(self.storage, "root", getattr(self.storage, "_root", getattr(self.storage, "base_path", None)))
            if storage_root is not None:
                meta_path = os.path.join(str(storage_root), f"{msg.file_hash}.meta")
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8-sig") as f:
                        file_name = json.load(f).get("file_name")
        except Exception as e:
            logger.error(f"CRASH while reading metadata: {e}")

        # ONLY ONE SEND MESSAGE AT THE VERY END
        await self._send_message(
            send_stream,
            FileInfoResponse(file_hash=msg.file_hash, file_size=file_size, file_name=file_name)
        )
    # -----------------------------------------------------------------------
    # Transfer — same trust-check + framing logic as the HTTP version
    # -----------------------------------------------------------------------

    async def _handle_transfer(
        self, msg: FileRequest, send_stream: "iroh.SendStream"
    ) -> None:
        if not self.dev_trust_all:
            try:
                result = await self.gateway.check_path(self.identity.agent_id, msg.sender_id)
            except GatewayError as e:
                logger.warning(
                    "gateway unreachable during transfer trust check for %s — rejecting: %s",
                    msg.sender_id[:12], e,
                )
                await self._send_message(
                    send_stream,
                    FileRequestReject(
                        request_id=msg.request_id,
                        reason="no_trust_path",
                        detail="trust gateway unreachable",
                    ),
                )
                return

            if not result.verified:
                await self._send_message(
                    send_stream,
                    FileRequestReject(
                        request_id=msg.request_id,
                        reason="no_trust_path",
                        detail=result.message or "no trust path to sender",
                    ),
                )
                return

            if (
                result.degrees_of_separation is not None
                and result.degrees_of_separation > self.trust_engine.max_depth
            ):
                await self._send_message(
                    send_stream,
                    FileRequestReject(
                        request_id=msg.request_id,
                        reason="no_trust_path",
                        detail=(
                            f"trust path exceeds max depth "
                            f"({result.degrees_of_separation} > {self.trust_engine.max_depth})"
                        ),
                    ),
                )
                return

        if not await self.storage.exists(msg.file_hash):
            await self._send_message(
                send_stream,
                FileRequestReject(
                    request_id=msg.request_id,
                    reason="file_not_found",
                    detail=f"no file with hash {msg.file_hash}",
                ),
            )
            return

        file_size = await self.storage.get_size(msg.file_hash)
        range_end = min(msg.range_end, file_size - 1)
        if msg.range_start > range_end:
            await self._send_message(
                send_stream,
                FileRequestReject(
                    request_id=msg.request_id,
                    reason="internal_error",
                    detail=(
                        f"invalid range [{msg.range_start}, {msg.range_end}] "
                        f"for file size {file_size}"
                    ),
                ),
            )
            return

        chunk_size = range_end - msg.range_start + 1
        ack = FileRequestAck(request_id=msg.request_id, chunk_size=chunk_size)

        # Same framing as the HTTP version's _stream_response: Ack, then
        # Header (with checksum), then raw bytes, then TransferComplete —
        # all written to the same stream, just an iroh stream instead of
        # an HTTP response body. Buffers the full range in memory to
        # compute the checksum first — same known limitation as before,
        # not something this migration step changes.
        await send_stream.write_all(encode(ack))
        await send_stream.write_all(b"\n")

        hasher = hashlib.sha256()
        total = 0
        chunks: list[bytes] = []
        byte_stream = await self.storage.read_range(msg.file_hash, msg.range_start, range_end)
        async for chunk in byte_stream:
            hasher.update(chunk)
            total += len(chunk)
            chunks.append(chunk)
        checksum = hasher.hexdigest()

        header = ChunkHeader(
            request_id=msg.request_id,
            range_start=msg.range_start,
            range_end=range_end,
            chunk_size=total,
            checksum=checksum,
        )
        await send_stream.write_all(encode(header))
        await send_stream.write_all(b"\n")

        for chunk in chunks:
            await send_stream.write_all(chunk)

        await send_stream.write_all(b"\n")
        complete = TransferComplete(request_id=msg.request_id, total_bytes=total)
        await send_stream.write_all(encode(complete))
        await send_stream.finish()
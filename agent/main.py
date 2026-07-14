# agent/main.py
from __future__ import annotations

import os
import asyncio
import logging
import signal
from pathlib import Path

import uvicorn

from agent.config import load_config
from agent.gateway_client import GatewayClient, GatewayError
from agent.identity import AgentIdentity
from agent.storage import LocalStorage
from agent.tracker_client import TrackerClient, TrackerError
from agent.trust import TrustEngine

logger = logging.getLogger(__name__)

KEEPALIVE_INTERVAL = 120.0  # seconds between tracker re-registrations


async def run(config_path: str = "config/settings.yaml") -> None:
    cfg = load_config(config_path)

    # Identity
    identity = AgentIdentity.load_or_create(cfg.trust.identity_path)
    logger.info("agent identity: %s", identity.agent_id[:16])

    # Trust engine
    trust_engine = TrustEngine(
        identity=identity,
        trust_anchors=set(cfg.trust.anchors),
        max_depth=cfg.trust.max_depth,
    )

    gateway = GatewayClient(cfg.gateway.url, identity)
    try:
        await gateway.register()
    except GatewayError as e:

        logger.error("gateway registration failed: %s", e)

    if cfg.storage.use_http and cfg.storage.server_url:
        from agent.http_storage_adapter import HTTPStorageAdapter
        storage = HTTPStorageAdapter(cfg.storage.server_url)
        logger.info("using HTTP storage backend: %s", cfg.storage.server_url)
    else:
        storage = LocalStorage(cfg.storage.root)
        logger.info("using local disk storage backend: %s", cfg.storage.root)


    tracker = TrackerClient(
        tracker_url=cfg.tracker.url,
        agent_id=identity.agent_id,
    )

    # P2P server — imported here to avoid circular imports at module level
    from agent.p2p_server import P2PServer
    p2p_server = P2PServer(
        identity=identity,
        trust_engine=trust_engine,
        storage=storage,
        gateway=gateway,
    )

    # Register with tracker
    seeded = await storage.list_files()
    if seeded:
        try:
            await tracker.register(seeded)
            logger.info("registered %d files with tracker", len(seeded))
        except TrackerError as e:

            logger.error("tracker registration failed: %s", e)

    # Graceful shutdown
    shutdown_event = asyncio.Event()

    def _handle_signal():
        logger.info("shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            #
            signal.signal(sig, lambda *_: _handle_signal())

    # Keepalive loop
    async def keepalive_loop():
        while not shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    asyncio.shield(shutdown_event.wait()),
                    timeout=KEEPALIVE_INTERVAL,
                )
                break  # shutdown was set
            except asyncio.TimeoutError:
                files = await storage.list_files()
                if files:
                    try:
                        await tracker.keepalive(files)
                        logger.debug("keepalive sent for %d files", len(files))
                    except TrackerError as e:
                        logger.warning("tracker keepalive failed: %s", e)

    # Run p2p server (iroh Endpoint) + keepalive concurrently until shutdown
    await p2p_server.start()

    from agent.downloader import Downloader
    downloader = Downloader(
        identity=identity,
        trust_engine=trust_engine,
        tracker=tracker,
        storage=storage,
        gateway=gateway,
        endpoint=p2p_server.endpoint,
    )


    from agent.control_api import build_control_api
    control_app = build_control_api(downloader)
    control_uv_config = uvicorn.Config(
        app=control_app,
        host="127.0.0.1",
        port=cfg.server.port,
        log_level="warning",
    )
    control_server = uvicorn.Server(control_uv_config)
    control_task = asyncio.create_task(control_server.serve())
    logger.info(
        "control API listening on http://127.0.0.1:%d (local only)", cfg.server.port
    )


    test_peer_id = os.environ.get("P2P_TEST_HANDSHAKE_PEER")
    if test_peer_id:
        from agent.downloader import _handshake_peer, _fetch_chunk, DownloadError
        from agent.tracker_client import PeerAddress
        import hashlib

        async def _run_test_handshake():
            logger.info("TEST: dialing %s...", test_peer_id[:12])
            peer = PeerAddress(agent_id=test_peer_id)
            accepted = await _handshake_peer(
                p2p_server.endpoint, peer, identity, gateway, trust_engine.max_depth
            )
            logger.info("TEST: handshake result = %s", "ACCEPTED" if accepted else "REJECTED")

            # Optional follow-up: exercise a real file transfer, bypassing
            # the tracker (not built yet — see tracker_client.py's client
            # side only). Set P2P_TEST_TRANSFER_FILE_HASH to a hash that
            # exists in the PEER's storage root.
            test_file_hash = os.environ.get("P2P_TEST_TRANSFER_FILE_HASH")
            if accepted and test_file_hash:
                logger.info("TEST: requesting file %s from %s...", test_file_hash[:12], test_peer_id[:12])
                try:
                    # Request a deliberately oversized range — p2p_server's
                    # _handle_transfer already clamps range_end to the
                    # real file size, so we don't need to know it upfront.
                    chunk = await _fetch_chunk(
                        p2p_server.endpoint, peer, identity,
                        test_file_hash, 0, 10**9,
                    )
                    actual_hash = hashlib.sha256(chunk.data).hexdigest()
                    logger.info(
                        "TEST: transfer OK — %d bytes, checksum verified=%s",
                        len(chunk.data), actual_hash == test_file_hash,
                    )
                    logger.info("TEST: content: %r", chunk.data[:200])
                except DownloadError as e:
                    logger.error("TEST: transfer FAILED: %s", e)

        asyncio.create_task(_run_test_handshake())

    try:
        await keepalive_loop()
    finally:
        control_server.should_exit = True
        control_task.cancel()
        await p2p_server.stop()
        await tracker.unregister()
        await tracker.close()
        await gateway.close()
        logger.info("agent shut down cleanly")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    asyncio.run(run())


if __name__ == "__main__":
    main()
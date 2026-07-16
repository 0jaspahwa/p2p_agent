# devtools/download_file.py
"""
Usage:
    python -m devtools.download_file \
        --identity config/identity_a.pem \
        --peer-agent-id <B_full_agent_id> \
        --file-hash <sha256_hex> \
        --file-size <exact_byte_size> \
        --output-dir ./downloads_test \
        --gateway-url http://127.0.0.1:3000
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
            
import iroh

from agent.config import load_config
from agent.identity import AgentIdentity
from agent.gateway_client import GatewayClient, GatewayError
from agent.storage import LocalStorage
from agent.tracker_client import PeerAddress, TrackerClient
from agent.trust import TrustEngine
from agent.downloader import Downloader, DownloadError
from agent.p2p_server import ALPN

logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", default=None, help="default: settings.yaml's trust.identity_path")
    parser.add_argument(
        "--peer-agent-id",
        default=None,
        help="if omitted, discover peers via the tracker instead (the real intended flow)",
    )
    parser.add_argument("--file-hash", required=True, help="sha256 hex of the file to download")
    parser.add_argument("--output-dir", default=None, help="default: settings.yaml's storage.root")
    parser.add_argument("--gateway-url", default=None, help="default: settings.yaml's gateway.url")
    parser.add_argument("--tracker-url", default=None, help="default: settings.yaml's tracker.url")
    parser.add_argument("--max-depth", type=int, default=None, help="default: settings.yaml's trust.max_depth")
    args = parser.parse_args()

    cfg = load_config()
    identity_path = args.identity or cfg.trust.identity_path
    output_dir = args.output_dir or cfg.storage.root
    gateway_url = args.gateway_url or os.environ.get("P2P_GATEWAY_URL") or cfg.gateway.url
    tracker_url = args.tracker_url or os.environ.get("P2P_TRACKER_URL") or cfg.tracker.url
    max_depth = args.max_depth if args.max_depth is not None else cfg.trust.max_depth

    identity = AgentIdentity.load_or_create(identity_path)
    logger.info("identity: %s", identity.agent_id)

    options = iroh.EndpointOptions(
        secret_key=identity.raw_private_bytes(),
        alpns=[ALPN],
        preset=iroh.preset_n0(),
    )
    endpoint = await iroh.Endpoint.bind(options)
    logger.info("endpoint bound: %s", endpoint.id().fmt_short())

    gateway = GatewayClient(gateway_url, identity)
    try:
        await gateway.register()
    except GatewayError as e:
        logger.warning("register() failed (may already be registered): %s", e)

    trust_engine = TrustEngine(identity=identity, max_depth=max_depth)
    storage = LocalStorage(output_dir)
    tracker = TrackerClient(tracker_url=tracker_url, agent_id=identity.agent_id)

    downloader = Downloader(
        identity=identity,
        trust_engine=trust_engine,
        tracker=tracker,
        storage=storage,
        gateway=gateway,
        endpoint=endpoint,
    )

    try:
        if args.peer_agent_id:
            logger.info("using manually specified peer: %s", args.peer_agent_id[:12])
            peer = PeerAddress(agent_id=args.peer_agent_id)
            result = await downloader.download_from_peers(args.file_hash, [peer])
        else:
            logger.info("discovering peers via tracker for %s...", args.file_hash[:12])
            result = await downloader.download(args.file_hash)

        print(f"DEBUG RESULT: {result}")
        if result.verified and result.file_name:

            # turning a verified download into an arbitrary file write.
            safe_name = os.path.basename(result.file_name) or result.file_hash

            # Get the internal storage path
            internal_path = os.path.join(downloader.storage.root, result.file_hash)
            export_path = os.path.join(os.getcwd(), safe_name)

            shutil.copy2(internal_path, export_path)
            print(f"\nSuccess! File exported as: {export_path}")

        logger.info(
            "DOWNLOAD COMPLETE: %d bytes, verified=%s, peers=%s",
            result.total_bytes, result.verified, [p[:12] for p in result.peers_used],
        )
        logger.info("saved to: %s/%s", output_dir, args.file_hash)
    except DownloadError as e:
        logger.error("DOWNLOAD FAILED: %s", e)
    finally:
        await endpoint.close()
        await gateway.close()
        await tracker.close()


if __name__ == "__main__":
    asyncio.run(main())
# devtools/test_handshake.py
"""
Dev-only utility: trigger a single _handshake_peer() call directly
against a running peer, without needing a tracker or a full
Downloader.download() flow. This is the fastest way to prove the trust-
check code path (gateway.check_path + identity match + max_depth) is
working, using nothing but two already-running `agent.main` processes
and the vouches set up via vouch_cli.py / revoke_cli.py.

Post-iroh migration: this now binds its own throwaway iroh Endpoint
under the CALLING agent's identity to dial the peer, the same way
devtools/download_file.py does — the old version predated the iroh
migration and called _handshake_peer with an httpx.AsyncClient and a
PeerAddress(host=..., port=...), neither of which match the current
transport (_handshake_peer expects a bound iroh.Endpoint; PeerAddress
only carries agent_id now — see tracker_client.py).

IMPORTANT: run this with the DIALING agent's own main.py process
stopped first — binding two Endpoints under the same secret key at once
is a real network identity collision, not just a Python-level conflict
(see download_file.py's docstring). The peer being dialed should stay
running as normal; only its full agent_id is needed now, no host/port,
since iroh resolves reachability by identity via discovery/relay.

Usage (run as Agent A, dialing Agent B):
    python -m devtools.test_handshake \
        --identity config/identity_a.pem \
        --peer-agent-id <B_full_agent_id> \
        --gateway-url http://127.0.0.1:3000 \
        --max-depth 3

Expect: "HANDSHAKE ACCEPTED" if the mutual vouch is in place, or a
specific rejection reason in the WARNING/INFO logs otherwise (bad
signature, identity mismatch, no trust path, gateway unreachable,
exceeds max_depth).

To prove the gateway's revoke race (controllers.js revokeVouch) is
actually fixed end-to-end, no lingering ACCEPTED window after a revoke:
    1. vouch_cli.py   --identity a.pem --target <B>
    2. test_handshake.py --identity a.pem --peer-agent-id <B>  -> ACCEPTED
    3. revoke_cli.py  --identity a.pem --target <B>
    4. test_handshake.py --identity a.pem --peer-agent-id <B>  -> REJECTED,
       immediately, on the very next call.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os

import iroh

from agent.identity import AgentIdentity
from agent.gateway_client import GatewayClient
from agent.tracker_client import PeerAddress
from agent.downloader import _handshake_peer
from agent.p2p_server import ALPN

logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, help="path to OUR identity.pem")
    parser.add_argument("--peer-agent-id", required=True, help="full agent_id of the peer to dial")
    parser.add_argument(
        "--gateway-url", default=os.environ.get("P2P_GATEWAY_URL", "http://localhost:3000")
    )
    parser.add_argument("--max-depth", type=int, default=3)
    args = parser.parse_args()

    identity = AgentIdentity.load_or_create(args.identity)
    print(f"our agent_id:  {identity.agent_id}")
    print(f"peer agent_id: {args.peer_agent_id}")

    # Bind a throwaway endpoint under OUR identity — same pattern as
    # download_file.py. Never the same endpoint our own main.py process
    # already bound; see the module docstring above.
    options = iroh.EndpointOptions(
        secret_key=identity.raw_private_bytes(),
        alpns=[ALPN],
        preset=iroh.preset_n0(),
    )
    endpoint = await iroh.Endpoint.bind(options)
    print(f"dialing endpoint bound: {endpoint.id().fmt_short()}")

    peer = PeerAddress(agent_id=args.peer_agent_id)

    try:
        async with GatewayClient(args.gateway_url, identity) as gateway:
            accepted = await _handshake_peer(
                endpoint, peer, identity, gateway, args.max_depth
            )
    finally:
        await endpoint.close()

    print()
    if accepted:
        print("✅ HANDSHAKE ACCEPTED — gateway confirmed a valid trust path.")
    else:
        print("❌ HANDSHAKE REJECTED — see WARNING/INFO logs above for the exact reason.")


if __name__ == "__main__":
    asyncio.run(main())
# devtools/revoke_cli.py
"""
Shortest path to revoking someone's vouch: with the console-script entry
point installed (pyproject.toml already has `revoke = "devtools.revoke_cli:cli_main"`),
this is just

    revoke <their_agent_id>

Mirrors vouch_cli.py exactly — same defaults (identity from settings.yaml's
trust.identity_path, gateway URL from settings.yaml unless overridden),
just calling gateway.revoke() instead of gateway.vouch_for().
"""
from __future__ import annotations

import argparse
import asyncio
import os

from agent.config import load_config
from agent.identity import AgentIdentity
from agent.gateway_client import GatewayClient, GatewayError


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Revoke a previously issued vouch for another agent."
    )
    parser.add_argument("target", help="agent_id of the vouch to revoke")
    parser.add_argument(
        "--identity", default=None,
        help="path to your identity.pem (default: config/identity.pem, or settings.yaml's trust.identity_path)",
    )
    parser.add_argument(
        "--gateway-url", default=None,
        help="override the gateway URL (default: settings.yaml's gateway.url, or P2P_GATEWAY_URL)",
    )
    args = parser.parse_args()

    cfg = load_config()
    identity_path = args.identity or cfg.trust.identity_path
    gateway_url = (
        args.gateway_url
        or os.environ.get("P2P_GATEWAY_URL")
        or cfg.gateway.url
    )

    identity = AgentIdentity.load_or_create(identity_path)
    print(f"issuer agent_id: {identity.agent_id}")
    print(f"revoking vouch for: {args.target}")
    print(f"via gateway:        {gateway_url}")

    async with GatewayClient(gateway_url, identity) as gateway:
        try:
            await gateway.revoke(args.target)
            print("✅ vouch revoked successfully")
        except GatewayError as e:
            print(f"🚨 revoke failed: {e}")


def cli_main() -> None:
    """Synchronous entry point for the `revoke` console script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
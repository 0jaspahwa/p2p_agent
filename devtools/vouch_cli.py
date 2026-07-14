# devtools/vouch_cli.py
"""
Shortest path to vouching for someone: with the console-script entry
point installed (see pyproject.toml), this is just

    vouch <their_agent_id>

--identity defaults to config/identity.pem, --gateway-url defaults to
whatever's in settings.yaml via load_config().
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
        description="Vouch for another agent, granting them trust from you."
    )
    parser.add_argument("target", help="agent_id of the agent to vouch for")
    parser.add_argument(
        "--identity", default=None,
        help="path to your identity.pem (default: config/identity.pem, or settings.yaml's trust.identity_path)",
    )
    parser.add_argument(
        "--gateway-url", default=None,
        help="override the gateway URL (default: settings.yaml's gateway.url, or P2P_GATEWAY_URL)",
    )
    parser.add_argument("--ttl-days", type=float, default=365.0)
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
    print(f"vouching for:    {args.target}")
    print(f"via gateway:     {gateway_url}")

    async with GatewayClient(gateway_url, identity) as gateway:
        try:
            await gateway.register()
        except GatewayError as e:
            print(f"note: register() failed (may already be registered): {e}")

        try:
            await gateway.vouch_for(args.target, ttl_seconds=args.ttl_days * 86400)
            print("✅ vouch issued successfully")
        except GatewayError as e:
            print(f"🚨 vouch failed: {e}")


def cli_main() -> None:
    """Synchronous entry point for the `vouch` console script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
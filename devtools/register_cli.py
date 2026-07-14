import asyncio
from agent.config import load_config
from agent.identity import AgentIdentity
from agent.gateway_client import GatewayClient

async def main():
    # 1. Load config and identity (generates one if missing)
    config = load_config()
    identity = AgentIdentity.load_or_create(config.trust.identity_path)
    print(f"My Agent ID: {identity.agent_id}")
    
    # 2. Connect to Gateway and register
    client = GatewayClient(config.gateway.url, identity)
    print(f"Connecting to Gateway at {config.gateway.url}...")
    
    try:
        await client.register()
        print("SUCCESS: Registered on the network!")
    except Exception as e:
        print(f"FAILED to register: {e}")

def cli_main():
    asyncio.run(main())

if __name__ == "__main__":
    cli_main()
# agent/config.py
from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class TrackerConfig(BaseModel):
    url: str = "http://localhost:8000"


class GatewayConfig(BaseModel):
    """
    Connection info for the Cryptographic Trust Gateway (the separate
    Node/Express + Postgres + Neo4j project). This is the authoritative
    source of trust decisions — see gateway_client.py.
    """
    url: str = "http://localhost:3002"


class ServerConfig(BaseModel):
    """
    NOTE: post-iroh-migration, this no longer configures an HTTP
    transport (iroh replaced that — see p2p_server.py). `port` is now
    reused for the local-only control API (see control_api.py). `host`
    is intentionally NOT used to configure the control API's bind
    address — main.py hardcodes that to 127.0.0.1 regardless of this
    config, since the control API must never be reachable from anywhere
    but the local machine. This field is kept for backward-compat config
    files and potential future use, not because it's currently load-bearing.
    """
    host: str = "127.0.0.1"
    port: int = 9000


class StorageConfig(BaseModel):
    """
    Google Drive support has been removed — this agent is direct
    peer-to-peer only. A peer serves files straight from its own local
    disk (LocalStorage); there is no cloud intermediary in the transfer
    path. use_http remains as an option for pointing at a plain static
    file server instead of local disk, which is still not a cloud
    service — it's read-only local infrastructure, not OAuth/Drive.
    """
    root: str = "./downloads"
    use_http: bool = False
    server_url: str = ""


class TrustConfig(BaseModel):
    max_depth: int = 3
    identity_path: str = "config/identity.pem"
    # Comma-separated base64 agent_ids to treat as trust anchors
    # beyond self. Empty by default — agent trusts only itself until
    # a vouch chain is established.
    anchors: list[str] = Field(default_factory=list)


class DownloaderConfig(BaseModel):
    max_peers: int = 4
    timeout: float = 30.0


class AgentConfig(BaseModel):
    tracker: TrackerConfig = Field(default_factory=TrackerConfig)
    gateway: GatewayConfig = Field(default_factory=GatewayConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    downloader: DownloaderConfig = Field(default_factory=DownloaderConfig)


def load_config(path: str | Path = "config/settings.yaml") -> AgentConfig:
    """
    Load config from a YAML file, falling back to defaults for any
    missing keys. Environment variables override file values:
        P2P_TRACKER_URL, P2P_GATEWAY_URL, P2P_SERVER_PORT, P2P_STORAGE_ROOT, etc.
    This lets Docker deployments configure via env without needing to
    mount a settings.yaml file.
    """
    path = Path(path)
    data: dict = {}

    if path.exists():
        with path.open() as f:
            data = yaml.safe_load(f) or {}

    config = AgentConfig.model_validate(data)

    # Environment variable overrides
    if url := os.environ.get("P2P_TRACKER_URL"):
        config.tracker.url = url
    if url := os.environ.get("P2P_GATEWAY_URL"):
        config.gateway.url = url
    if port := os.environ.get("P2P_SERVER_PORT"):
        config.server.port = int(port)
    if root := os.environ.get("P2P_STORAGE_ROOT"):
        config.storage.root = root
    if depth := os.environ.get("P2P_TRUST_MAX_DEPTH"):
        config.trust.max_depth = int(depth)
    if host := os.environ.get("P2P_ADVERTISE_HOST"):
        config.server.host = host
    if os.environ.get("P2P_USE_HTTP_STORAGE", "").lower() == "true":
        config.storage.use_http = True
    if identity_path := os.environ.get("P2P_IDENTITY_PATH"):
        config.trust.identity_path = identity_path
    if url := os.environ.get("P2P_STORAGE_SERVER_URL"):
        config.storage.server_url = url

    return config
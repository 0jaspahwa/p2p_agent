# agent/identity.py
from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class IdentityError(Exception):
    """Raised for key generation, loading, or encoding failures."""


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception as e:
        raise IdentityError(f"invalid base64: {e}") from e


class AgentIdentity:
    """
    Wraps a single agent's Ed25519 keypair. This is the only place private
    key material is held in memory. trust.py and the rest of the agent only
    ever see agent_id (the base64 public key) plus sign()/verify() — they
    never touch raw key bytes directly.
    """

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()

    @property
    def agent_id(self) -> str:
        """Base64-encoded raw 32-byte Ed25519 public key. This is the
        canonical identity string used everywhere else in the protocol
        (issuer_id, subject_id, sender_id, etc in messages.py)."""
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64encode(raw)

    def sign(self, data: bytes) -> str:
        """Sign raw bytes, return base64-encoded signature.
        Caller is responsible for producing a canonical byte representation
        of whatever's being signed — identity.py doesn't know about Vouch,
        HandshakeRequest, etc, only raw bytes."""
        sig = self._private_key.sign(data)
        return _b64encode(sig)

    def raw_private_bytes(self) -> bytes:
        """
        Return the raw 32-byte Ed25519 private key.

        This is a deliberate, narrow exception to this class's usual rule
        of never letting private key material leave its abstraction (see
        the class docstring). It exists for exactly one purpose: feeding
        this agent's existing identity into iroh's
        EndpointOptions(secret_key=...), which expects raw private key
        bytes, so that the SAME identity is used for both gateway trust
        (Ed25519 signing) and iroh transport (Ed25519-derived EndpointId) —
        rather than iroh generating a second, unrelated identity that the
        gateway has never heard of.

        Callers must not log, persist, or transmit the return value
        anywhere except directly into iroh's own EndpointOptions
        construction.
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def verify(agent_id: str, data: bytes, signature: str) -> bool:
        """Verify that `signature` over `data` was produced by the private
        key matching `agent_id` (base64 pubkey). Returns False on any
        failure — bad signature, malformed base64, wrong key length —
        rather than raising, since callers (trust.py) want a clean bool
        for 'is this vouch valid' without a try/except at every call site."""
        try:
            raw_pubkey = _b64decode(agent_id)
            public_key = Ed25519PublicKey.from_public_bytes(raw_pubkey)
            raw_sig = _b64decode(signature)
            public_key.verify(raw_sig, data)
            return True
        except (InvalidSignature, IdentityError, ValueError):
            return False

    # --- persistence ---

    @classmethod
    def generate(cls) -> "AgentIdentity":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, path: str | Path) -> "AgentIdentity":
        """Load a persisted private key from `path` if it exists, otherwise
        generate a fresh keypair and persist it there. This is what gives
        an agent a stable identity across restarts — without this, every
        restart would produce a new agent_id, silently invalidating every
        Vouch anyone had issued to the old one."""
        path = Path(path)
        if path.exists():
            return cls._load(path)
        identity = cls.generate()
        identity._save(path)
        return identity

    @classmethod
    def _load(cls, path: Path) -> "AgentIdentity":
        try:
            pem_bytes = path.read_bytes()
            private_key = serialization.load_pem_private_key(pem_bytes, password=None)
        except Exception as e:
            raise IdentityError(f"failed to load identity from {path}: {e}") from e
        if not isinstance(private_key, Ed25519PrivateKey):
            raise IdentityError(f"key at {path} is not an Ed25519 private key")
        return cls(private_key)

    def _save(self, path: Path) -> None:
        # NOTE: stored unencrypted at rest. Acceptable for a portfolio/demo
        # project; a production version would add passphrase-based
        # encryption here (serialization.BestAvailableEncryption(...)).
        path.parent.mkdir(parents=True, exist_ok=True)
        pem_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(pem_bytes)
        path.chmod(0o600)
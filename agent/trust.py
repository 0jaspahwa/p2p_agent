# agent/trust.py
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import NamedTuple

from agent.identity import AgentIdentity
from agent.messages import Revoke, Vouch


def _vouch_signing_bytes(
    issuer_id: str,
    subject_id: str,
    issued_at: float,
    expires_at: float,
) -> bytes:
    return f"{issuer_id}|{subject_id}|{issued_at}|{expires_at}".encode("utf-8")


def _revoke_signing_bytes(
    issuer_id: str,
    subject_id: str,
    revoked_at: float,
) -> bytes:
    return f"{issuer_id}|{subject_id}|{revoked_at}".encode("utf-8")




class TrustResult(NamedTuple):
    trusted: bool
    reason: str          
    depth: int = 0       # how many hops from subject back to a trust anchor



# TrustEngine
@dataclass
class TrustEngine:


    identity: AgentIdentity
    trust_anchors: set[str] = field(default_factory=set)
    max_depth: int = 3

    # (issuer_id, subject_id) pairs that have been explicitly revoked
    _revocations: set[tuple[str, str]] = field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        self.trust_anchors.add(self.identity.agent_id)

    #issuing
    def issue_vouch(self, subject_id: str, ttl_seconds: float = 86400.0) -> Vouch:
        """Issue a signed Vouch from this agent's identity to subject_id."""
        now = time.time()
        expires_at = now + ttl_seconds
        signing_bytes = _vouch_signing_bytes(
            self.identity.agent_id, subject_id, now, expires_at
        )
        return Vouch(
            issuer_id=self.identity.agent_id,
            subject_id=subject_id,
            issued_at=now,
            expires_at=expires_at,
            signature=self.identity.sign(signing_bytes),
        )

    def issue_revoke(self, subject_id: str, reason: str = "") -> Revoke:
        """Revoke a previously issued vouch for subject_id."""
        now = time.time()
        signing_bytes = _revoke_signing_bytes(
            self.identity.agent_id, subject_id, now
        )
        revoke = Revoke(
            issuer_id=self.identity.agent_id,
            subject_id=subject_id,
            revoked_at=now,
            reason=reason,
            signature=self.identity.sign(signing_bytes),
        )
        self._revocations.add((self.identity.agent_id, subject_id))
        return revoke

    # --- consuming ---

    def apply_revoke(self, revoke: Revoke) -> bool:
        signing_bytes = _revoke_signing_bytes(
            revoke.issuer_id, revoke.subject_id, revoke.revoked_at
        )
        if not AgentIdentity.verify(revoke.issuer_id, signing_bytes, revoke.signature):
            return False
        self._revocations.add((revoke.issuer_id, revoke.subject_id))
        return True

    def is_revoked(self, issuer_id: str, subject_id: str) -> bool:
        return (issuer_id, subject_id) in self._revocations

    #chain verification 

    def verify_vouch_signature(self, vouch: Vouch) -> bool:
        """Verify the cryptographic signature on a single Vouch edge."""
        signing_bytes = _vouch_signing_bytes(
            vouch.issuer_id, vouch.subject_id, vouch.issued_at, vouch.expires_at
        )
        return AgentIdentity.verify(vouch.issuer_id, signing_bytes, vouch.signature)

    def verify_chain(
        self,
        subject_id: str,
        chain: list[Vouch],
        now: float | None = None,
    ) -> TrustResult:
    
        if now is None:
            now = time.time()

        # Fast path: subject is already a known-trusted anchor.
        if subject_id in self.trust_anchors:
            return TrustResult(trusted=True, reason="subject is a trust anchor", depth=0)

        if not chain:
            return TrustResult(trusted=False, reason="no trust chain provided", depth=0)

        if len(chain) > self.max_depth:
            return TrustResult(
                trusted=False,
                reason=f"chain depth {len(chain)} exceeds max_depth {self.max_depth}",
                depth=len(chain),
            )

        # Chain root must come from a trust anchor.
        if chain[0].issuer_id not in self.trust_anchors:
            return TrustResult(
                trusted=False,
                reason=f"chain root issuer {chain[0].issuer_id[:12]}… is not a trust anchor",
                depth=len(chain),
            )

        # Walk each edge in order.
        for depth, vouch in enumerate(chain, start=1):
            # 1. Signature
            if not self.verify_vouch_signature(vouch):
                return TrustResult(
                    trusted=False,
                    reason=f"invalid signature at chain depth {depth}",
                    depth=depth,
                )
            # 2. Expiry
            if vouch.expires_at < now:
                return TrustResult(
                    trusted=False,
                    reason=f"vouch at depth {depth} expired at {vouch.expires_at:.0f}",
                    depth=depth,
                )
            # 3. Revocation
            if self.is_revoked(vouch.issuer_id, vouch.subject_id):
                return TrustResult(
                    trusted=False,
                    reason=f"vouch at depth {depth} has been revoked",
                    depth=depth,
                )
            # 4. Continuity: each edge's subject must be the next edge's issuer.
            if depth < len(chain):
                next_vouch = chain[depth]   # chain is 0-indexed; depth started at 1
                if vouch.subject_id != next_vouch.issuer_id:
                    return TrustResult(
                        trusted=False,
                        reason=(
                            f"chain break between depth {depth} and {depth + 1}: "
                            f"subject {vouch.subject_id[:12]}… ≠ "
                            f"issuer {next_vouch.issuer_id[:12]}…"
                        ),
                        depth=depth,
                    )

        # Final edge must terminate at the claimed subject.
        if chain[-1].subject_id != subject_id:
            return TrustResult(
                trusted=False,
                reason=(
                    f"chain terminus {chain[-1].subject_id[:12]}… "
                    f"does not match claimed subject {subject_id[:12]}…"
                ),
                depth=len(chain),
            )

        return TrustResult(trusted=True, reason="valid trust chain", depth=len(chain))
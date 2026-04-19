from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StatusList:
    version: int
    revoked_ids: frozenset
    issued_at: float   # simulation time when issuer created this
    ttl: float         # seconds until stale

    def is_expired(self, current_time: float) -> bool:
        return current_time > self.issued_at + self.ttl

    # Byte size approximation: 4 bytes per revoked ID + fixed overhead
    def byte_size(self) -> int:
        return 64 + len(self.revoked_ids) * 4


@dataclass
class RevocationEvent:
    credential_id: int
    revoked_at: float  # simulation time


@dataclass
class VerificationAttempt:
    node_id: int
    credential_id: int
    sim_time: float
    was_revoked: bool        # ground truth at time of check
    node_knew: bool          # did the node's list include this revocation
    list_age: float          # how old was the cached list (seconds)


@dataclass
class NodeStats:
    node_id: int
    bytes_transferred: int = 0
    fetch_count: int = 0
    stale_hits: int = 0      # fetches skipped because offline
    max_list_bytes: int = 0

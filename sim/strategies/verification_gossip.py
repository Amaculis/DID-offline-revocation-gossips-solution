"""VERIFICATION-GOSSIP strategy.

List propagation happens exclusively at the moment of credential verification.
When a node verifies a credential it first does a bidirectional version swap
with a randomly chosen peer, then checks the credential against its (now
possibly updated) local cache.

No background gossip, no refresh, no push from Issuer.
is_online controls Issuer access only; local peer exchange always works.
"""
from __future__ import annotations
import random
import simpy
from ..common.models import StatusList, VerificationAttempt, NodeStats
from ..common.issuer import Issuer


class VerificationGossipNode:

    def __init__(
        self,
        node_id: int,
        env: simpy.Environment,
        issuer: Issuer,
        is_online: bool,
        rng: random.Random,
        offline_ratio: float,
        mean_online_duration: float = 3600,
        mean_offline_duration: float = 14400,
        is_dead: bool = False,
    ):
        self.node_id = node_id
        self.env = env
        self.issuer = issuer
        self.rng = rng
        self.offline_ratio = offline_ratio
        self.mean_online = mean_online_duration
        self.mean_offline = mean_offline_duration
        self.is_dead = is_dead

        self.is_online = is_online
        self.cached_list: StatusList | None = None
        self.stats = NodeStats(node_id=node_id)
        self.verification_log: list[VerificationAttempt] = []
        self.awareness_times: dict[int, float] = {}

        self.peers: list[VerificationGossipNode] = []

        self._initial_fetch()

        env.process(self._connectivity_process())
        env.process(self._verify_process())

    def _initial_fetch(self):
        if self.is_dead:
            return
        fresh = self.issuer.current_list
        self.cached_list = fresh
        size = fresh.byte_size()
        self.stats.bytes_transferred += size
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, size)
        for cid in fresh.revoked_ids:
            self.awareness_times.setdefault(cid, self.env.now)

    def _connectivity_process(self):
        while True:
            if self.is_online:
                duration = self.rng.expovariate(1 / self.mean_online)
                yield self.env.timeout(duration)
                self.is_online = False
            else:
                duration = self.rng.expovariate(1 / self.mean_offline)
                yield self.env.timeout(duration)
                self.is_online = True

    def _verify_process(self):
        mean_verify_interval = 3600
        while True:
            delay = self.rng.expovariate(1 / mean_verify_interval)
            yield self.env.timeout(delay)

            if self.peers:
                peer = self.rng.choice(self.peers)
                self._exchange_list(peer)

            self._do_verify()

    def _exchange_list(self, peer: VerificationGossipNode):
        self_ver = self.cached_list.version if self.cached_list else -1
        peer_ver = peer.cached_list.version if peer.cached_list else -1

        if self_ver > peer_ver:
            peer._absorb(self.cached_list)
            self.stats.bytes_transferred += self.cached_list.byte_size()
        elif peer_ver > self_ver:
            self._absorb(peer.cached_list)
            peer.stats.bytes_transferred += peer.cached_list.byte_size()

    def _absorb(self, new_list: StatusList) -> None:
        if new_list is None:
            return
        current_ver = self.cached_list.version if self.cached_list else -1
        if new_list.version <= current_ver:
            return
        prev_revoked = set(self.cached_list.revoked_ids) if self.cached_list else set()
        self.cached_list = new_list
        size = new_list.byte_size()
        self.stats.bytes_transferred += size
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, size)
        for cid in set(new_list.revoked_ids) - prev_revoked:
            if cid not in self.awareness_times:
                self.awareness_times[cid] = self.env.now

    def _do_verify(self):
        if not self.issuer.credentials:
            return
        cred_id = self.rng.choice(self.issuer.credentials)
        ground_truth = self.issuer.is_revoked(cred_id)
        if self.cached_list is None:
            node_knew = False
            list_age = float("inf")
        else:
            node_knew = cred_id in self.cached_list.revoked_ids
            list_age = self.env.now - self.cached_list.issued_at
        self.verification_log.append(
            VerificationAttempt(
                node_id=self.node_id,
                credential_id=cred_id,
                sim_time=self.env.now,
                was_revoked=ground_truth,
                node_knew=node_knew,
                list_age=list_age,
            )
        )

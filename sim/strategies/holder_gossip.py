"""HOLDER-GOSSIP strategy.

Two node types:
  HolderGossipNode — verifier; gossips with peers AND receives list updates
                     from holders during credential presentations.
  HolderNode       — credential holder; cannot reach the Issuer directly;
                     only receives a StatusList through presentation exchanges
                     with verifiers, then carries it to the next verifier.
"""
from __future__ import annotations
import random
import simpy
from ..common.models import StatusList, VerificationAttempt, NodeStats
from ..common.issuer import Issuer


# ---------------------------------------------------------------------------
# HolderGossipNode (verifier)
# ---------------------------------------------------------------------------

class HolderGossipNode:
    """Verifier node — identical to GossipNode with holder-list reception added."""

    _REFRESH_CHECK = 300  # seconds between TTL-expiry checks

    def __init__(
        self,
        node_id: int,
        env: simpy.Environment,
        issuer: Issuer,
        is_online: bool,
        rng: random.Random,
        offline_ratio: float,
        mean_online_duration: float = 7200,
        mean_offline_duration: float = 1800,
        contact_rate: float = 1 / 600,
        is_dead: bool = False,
    ):
        self.node_id = node_id
        self.env = env
        self.issuer = issuer
        self.rng = rng
        self.offline_ratio = offline_ratio
        self.mean_online = mean_online_duration
        self.mean_offline = mean_offline_duration
        self.contact_rate = contact_rate
        self.is_dead = is_dead

        self.is_online = is_online
        self.cached_list: StatusList | None = None
        self.stats = NodeStats(node_id=node_id)
        self.verification_log: list[VerificationAttempt] = []
        self.awareness_times: dict[int, float] = {}

        self.peers: list[HolderGossipNode] = []   # verifier↔verifier gossip
        self.holders: list[HolderNode] = []        # informational; holders initiate

        self._initial_fetch()

        env.process(self._connectivity_process())
        env.process(self._refresh_process())
        env.process(self._gossip_process())
        env.process(self._verify_process())

    def _initial_fetch(self):
        fresh = self.issuer.current_list
        self.cached_list = fresh
        size = fresh.byte_size()
        self.stats.bytes_transferred += size
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, size)
        for cid in fresh.revoked_ids:
            self.awareness_times.setdefault(cid, self.env.now)

    def _connectivity_process(self):
        if self.is_dead:
            return
        while True:
            if self.is_online:
                duration = self.rng.expovariate(1 / self.mean_online)
                yield self.env.timeout(duration)
                self.is_online = False
            else:
                duration = self.rng.expovariate(1 / self.mean_offline)
                yield self.env.timeout(duration)
                self.is_online = True

    def _refresh_process(self):
        while True:
            yield self.env.timeout(self._REFRESH_CHECK)
            if not self.is_online:
                continue
            if self.cached_list is None or self.cached_list.is_expired(self.env.now):
                self._fetch_from_issuer()

    def _fetch_from_issuer(self):
        fresh = self.issuer.current_list
        if fresh.version <= (self.cached_list.version if self.cached_list else -1):
            return
        prev_revoked = set(self.cached_list.revoked_ids) if self.cached_list else set()
        self.cached_list = fresh
        size = fresh.byte_size()
        self.stats.bytes_transferred += size
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, size)
        for cid in set(fresh.revoked_ids) - prev_revoked:
            self.awareness_times.setdefault(cid, self.env.now)

    def _gossip_process(self):
        while True:
            delay = self.rng.expovariate(self.contact_rate)
            yield self.env.timeout(delay)

            if not self.is_online:
                self.stats.stale_hits += 1
                continue
            if not self.peers:
                continue

            peer: HolderGossipNode = self.rng.choice(self.peers)
            if not peer.is_online:
                continue

            self_ver = self.cached_list.version if self.cached_list else -1
            peer_ver = peer.cached_list.version if peer.cached_list else -1

            if self_ver > peer_ver:
                self._transfer_to(peer)
            elif peer_ver > self_ver:
                peer._transfer_to(self)

    def _transfer_to(self, peer: HolderGossipNode):
        peer.receive_gossip(self.cached_list)
        self.stats.bytes_transferred += self.cached_list.byte_size()  # sender upload

    def receive_gossip(self, new_list: StatusList) -> None:
        self._absorb(new_list)

    def receive_holder_list(self, new_list: StatusList) -> None:
        """Accept a list pushed by a holder during credential presentation."""
        self._absorb(new_list)

    def _absorb(self, new_list: StatusList) -> None:
        """Common acceptance logic for gossip and holder-push."""
        if new_list is None:
            return
        current_ver = self.cached_list.version if self.cached_list else -1
        if new_list.version <= current_ver:
            return
        prev_revoked = set(self.cached_list.revoked_ids) if self.cached_list else set()
        self.cached_list = new_list
        size = new_list.byte_size()
        self.stats.bytes_transferred += size   # receiver download
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, size)
        for cid in set(new_list.revoked_ids) - prev_revoked:
            if cid not in self.awareness_times:
                self.awareness_times[cid] = self.env.now

    def _verify_process(self):
        mean_verify_interval = 3600
        while True:
            delay = self.rng.expovariate(1 / mean_verify_interval)
            yield self.env.timeout(delay)
            self._do_verify()

    def _do_verify(self):
        if not self.issuer.credentials:
            return
        cred_id = self.rng.choice(self.issuer.credentials)
        self._log_verification(cred_id)

    def _do_verify_holder(self, holder: HolderNode):
        """Log a verification triggered by a holder presentation."""
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
                is_presentation=True,
            )
        )

    def _log_verification(self, cred_id: int):
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


# ---------------------------------------------------------------------------
# HolderNode (credential holder)
# ---------------------------------------------------------------------------

class HolderNode:
    """Credential holder — cannot reach the Issuer; gets StatusList only via
    presentation exchanges with verifiers."""

    def __init__(
        self,
        node_id: int,
        env: simpy.Environment,
        issuer: Issuer,
        is_online: bool,
        rng: random.Random,
        mean_online_duration: float = 7200,
        mean_offline_duration: float = 1800,
        mean_presentation_interval: float = 7200,  # present credential every ~2h
        is_dead: bool = False,
    ):
        self.node_id = node_id
        self.env = env
        self.issuer = issuer
        self.rng = rng
        self.mean_online = mean_online_duration
        self.mean_offline = mean_offline_duration
        self.mean_presentation_interval = mean_presentation_interval
        self.is_dead = is_dead

        self.is_online = is_online
        self.cached_list: StatusList | None = None   # starts empty — no issuer access
        self.stats = NodeStats(node_id=node_id)
        self.verification_log: list[VerificationAttempt] = []  # always empty
        self.awareness_times: dict[int, float] = {}

        self.verifiers: list[HolderGossipNode] = []  # set by runner
        self.is_holder = True  # marker for metrics — avoids circular import

        env.process(self._connectivity_process())
        env.process(self._presentation_process())

    def _connectivity_process(self):
        if self.is_dead:
            return
        while True:
            if self.is_online:
                duration = self.rng.expovariate(1 / self.mean_online)
                yield self.env.timeout(duration)
                self.is_online = False
            else:
                duration = self.rng.expovariate(1 / self.mean_offline)
                yield self.env.timeout(duration)
                self.is_online = True

    def _presentation_process(self):
        if self.is_dead:
            return
        while True:
            delay = self.rng.expovariate(1 / self.mean_presentation_interval)
            yield self.env.timeout(delay)

            if not self.is_online or not self.verifiers:
                continue
            #verifier = self.rng.choice(self.verifiers)
            verifier = self.rng.choice(self.verifiers)
            if not verifier.is_online:
                continue

            self._exchange_list(verifier)
            verifier._do_verify_holder(self)

    def _exchange_list(self, verifier: HolderGossipNode):
        """Bidirectional version swap. Holder only sends non-expired lists."""
        holder_ver = self.cached_list.version if self.cached_list else -1
        verifier_ver = verifier.cached_list.version if verifier.cached_list else -1

        if holder_ver > verifier_ver:
            # Only send if the holder's list is still fresh
            if self.cached_list and not self.cached_list.is_expired(self.env.now):
                size = self.cached_list.byte_size()
                self.stats.bytes_transferred += size        # holder upload
                verifier.receive_holder_list(self.cached_list)
        elif verifier_ver > holder_ver:
            if verifier.cached_list:
                size = verifier.cached_list.byte_size()
                verifier.stats.bytes_transferred += size    # verifier upload
                self._accept_list(verifier.cached_list)

    def _accept_list(self, new_list: StatusList):
        """Passively accept a newer list from a verifier."""
        current_ver = self.cached_list.version if self.cached_list else -1
        if new_list.version <= current_ver:
            return
        prev_revoked = set(self.cached_list.revoked_ids) if self.cached_list else set()
        self.cached_list = new_list
        size = new_list.byte_size()
        self.stats.bytes_transferred += size    # holder download
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, size)
        for cid in set(new_list.revoked_ids) - prev_revoked:
            self.awareness_times.setdefault(cid, self.env.now)

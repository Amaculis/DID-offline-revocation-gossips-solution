from __future__ import annotations
import random
import simpy
from ..common.models import StatusList, VerificationAttempt, NodeStats
from ..common.issuer import Issuer
class GossipNode:
    def __init__(
        self,
        node_id: int,
        env: simpy.Environment,
        issuer: Issuer,
        is_online: bool,
        rng: random.Random,
        mean_online_duration: float = 3600,   # 1h
        mean_offline_duration: float = 14400,  # 4h
        contact_rate: float = 1 / 600,        # gossip contacts per second (mean gap between contacts = 1/contact_rate)
        is_dead: bool = False,
        is_seed: bool = False,  # Seed nodes have direct issuer access; the rest rely on gossip / holder exchange only
    ):
        self.node_id = node_id
        self.env = env
        self.issuer = issuer
        self.rng = rng
        self.mean_online = mean_online_duration
        self.mean_offline = mean_offline_duration
        self.contact_rate = contact_rate
        self.is_dead = is_dead
        self.is_seed = is_seed

        self.is_online = is_online
        self.cached_list: StatusList | None = None
        self.stats = NodeStats(node_id=node_id)
        self.verification_log: list[VerificationAttempt] = []
        self.awareness_times: dict[int, float] = {}

        # Filled in by the simulation runner after node creation, based on the graph topology.
        self.peers: list[GossipNode] = []

        # Take the initial list from the issuer so version comparison works
        self._initial_fetch()

        env.process(self._connectivity_process())
        if self.is_seed:
            env.process(self._refresh_process())
        env.process(self._gossip_process())
        env.process(self._verify_process())

    # Initial list fetch. Not counted as a normal fetch: it guarantees that at least one
    # node starts with the latest list and can spread it to the others via gossip.
    def _initial_fetch(self):
        if self.is_dead or not self.is_seed:
            return  # only seed nodes fetch from issuer
        fresh = self.issuer.current_list
        self.cached_list = fresh
        bytes_rx = fresh.byte_size()
        self.stats.bytes_transferred += bytes_rx
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, bytes_rx)
        for cid in fresh.revoked_ids:
            self.awareness_times.setdefault(cid, self.env.now)


    # Connectivity: same model as PULL

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

    # ------------------------------------------------------------------
    # TTL refresh: fetch fresh data from the issuer once the cache has expired.
    # Gossip can only spread what some node has already fetched; this process
    # ensures at least one node picks up the latest version, after which the
    # gossip network spreads it peer-to-peer.
    # ------------------------------------------------------------------
    _REFRESH_CHECK = 300  # check every 5 sim-minutes

    def _refresh_process(self):
        while True:
            yield self.env.timeout(self._REFRESH_CHECK)
            if not self.is_online or self.is_dead:
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

    # ------------------------------------------------------------------
    # On a random meeting, compare list versions and send the newer one to the other side.
    # If a node has no peers, it simply waits for the next contact.
    # (Gossip runs independently of is_online.)
    # ------------------------------------------------------------------
    def _gossip_process(self):
        while True:
            delay = self.rng.expovariate(self.contact_rate)
            yield self.env.timeout(delay)

            if not self.peers:
                continue

            peer: GossipNode = self.rng.choice(self.peers)

            # Compare versions so that older lists are never accepted or spread
            # (they could be malicious or simply stale).
            self_ver = self.cached_list.version if self.cached_list else -1
            peer_ver = peer.cached_list.version if peer.cached_list else -1

            if self_ver > peer_ver:
                self._transfer_to(peer)
            elif peer_ver > self_ver:
                peer._transfer_to(self)
            # Equal versions: both nodes already know the same revocations, nothing to send.

    def _transfer_to(self, peer: GossipNode):
        peer.receive_gossip(self.cached_list)


    def receive_gossip(self, new_list: StatusList) -> None:
        if new_list is None:
            return
        current_ver = self.cached_list.version if self.cached_list else -1
        if new_list.version <= current_ver:
            return   # Reject anything that is not strictly newer. Gossip only moves forward, never back,
            # which protects against replay of old (possibly malicious) lists.

        prev_revoked = set(self.cached_list.revoked_ids) if self.cached_list else set()

        self.cached_list = new_list
        size = new_list.byte_size()
        self.stats.bytes_transferred += size  # the receiver pays for the download
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, size)

        newly_known = set(new_list.revoked_ids) - prev_revoked
        for cid in newly_known:
            if cid not in self.awareness_times:
                self.awareness_times[cid] = self.env.now

    # Verification: identical to PULL
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

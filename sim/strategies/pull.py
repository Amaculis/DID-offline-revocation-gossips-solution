from __future__ import annotations
import random
import simpy
from ..common.models import StatusList, VerificationAttempt, NodeStats
from ..common.issuer import Issuer

# How often a node checks whether its list needs refreshing (simulated seconds)
CHECK_INTERVAL = 300  # every 5 min

class PullNode:
    def __init__(
        self,
        node_id: int,
        env: simpy.Environment,
        issuer: Issuer,
        is_online: bool,
        rng: random.Random,
        # mean online / offline durations, drawn from exponential distributions
        mean_online_duration: float = 3600,   # 1h
        mean_offline_duration: float = 14400,  # 4h
        is_dead: bool = False,
    ):
        self.node_id = node_id
        self.env = env
        self.issuer = issuer
        self.rng = rng
        self.mean_online = mean_online_duration
        self.mean_offline = mean_offline_duration
        self.is_dead = is_dead

        self.is_online = is_online
        self.cached_list: StatusList | None = None
        self.stats = NodeStats(node_id=node_id)
        self.verification_log: list[VerificationAttempt] = []

        env.process(self._connectivity_process())
        env.process(self._pull_process())
        env.process(self._verify_process())

    # Connectivity: randomly toggles online/offline with the given mean time between switches
    
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
    
    # PULL logic: periodically checks whether the list can be refreshed
    def _pull_process(self):
        while True:
            yield self.env.timeout(CHECK_INTERVAL)
            if not self.is_online:
                if self.cached_list is not None and self.cached_list.is_expired(self.env.now):
                    self.stats.stale_hits += 1
                continue

            # Online: refresh the cache if it is missing or expired
            if not self.is_dead and (self.cached_list is None or self.cached_list.is_expired(self.env.now)):
                self._fetch()

    def _fetch(self):
        fresh = self.issuer.current_list
        
        if fresh.version <= (self.cached_list.version if self.cached_list else -1):
            return
        prev_revoked = set(self.cached_list.revoked_ids) if self.cached_list else set()
    
        self.cached_list = fresh
        bytes_rx = fresh.byte_size()
        self.stats.bytes_transferred += bytes_rx
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, bytes_rx)

        for cid in set(fresh.revoked_ids) - prev_revoked:
            self.awareness_times.setdefault(cid, self.env.now)

    
    # Periodic verification: checks the status of a random credential and records the result against ground truth

    def _verify_process(self):
        
        mean_verify_interval = 3600 # verifies once per hour on average
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

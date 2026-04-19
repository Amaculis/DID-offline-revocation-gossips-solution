"""PULL strategy: nodes fetch the status list when online and their cache is expired."""
from __future__ import annotations
import random
import simpy
from ..common.models import StatusList, VerificationAttempt, NodeStats
from ..common.issuer import Issuer


# Cik bieži mezgls pārbauda, vai ir jāatjauno saraksts (sekundēs simulaācijas laikā)
CHECK_INTERVAL = 300  # Katras 5 min 


class PullNode:
    def __init__(
        self,
        node_id: int,
        env: simpy.Environment,
        issuer: Issuer,
        is_online: bool,
        rng: random.Random,
        offline_ratio: float,
        # vidējais laiks online / offline, kas tiek zīmēts no eksponenciālām sadalījumiem
        mean_online_duration: float = 7200,   # 2h
        mean_offline_duration: float = 1800,  # 30min
    ):
        self.node_id = node_id
        self.env = env
        self.issuer = issuer
        self.rng = rng
        self.offline_ratio = offline_ratio
        self.mean_online = mean_online_duration
        self.mean_offline = mean_offline_duration

        self.is_online = is_online
        self.cached_list: StatusList | None = None
        self.stats = NodeStats(node_id=node_id)
        self.verification_log: list[VerificationAttempt] = []

        env.process(self._connectivity_process())
        env.process(self._pull_process())
        env.process(self._verify_process())

    # ------------------------------------------------------------------
    # Connectivity: Nejauši pārliek online vai offline ar noteiktu vidējo laiku starp pārslēgumiem
    # ------------------------------------------------------------------
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
    # PULL loģika: Ik pēc noteikta laika pārbauda vai ir iespējams atjaunot sarakstu
    # ------------------------------------------------------------------
    def _pull_process(self):
        while True:
            yield self.env.timeout(CHECK_INTERVAL)
            if not self.is_online:
                if self.cached_list is not None and self.cached_list.is_expired(self.env.now):
                    self.stats.stale_hits += 1
                continue

            # Online — pārbauda, vai kešatmiņa ir novecojusi vai trūkst, un ja jā, tad atjauno
            if self.cached_list is None or self.cached_list.is_expired(self.env.now):
                self._fetch()

    def _fetch(self):
        fresh = self.issuer.current_list
        self.cached_list = fresh
        bytes_rx = fresh.byte_size()
        self.stats.bytes_transferred += bytes_rx
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, bytes_rx)

    # ------------------------------------------------------------------
    # Peridodiska pārbaude. Reizi noteiktajā laikā pārbauda nejaušu akreditācijas datu statusu un reģistrē rezultātu, salīdzinot ar patiesību
    # ------------------------------------------------------------------
    def _verify_process(self):
        # Nodes verify roughly once per hour on average
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

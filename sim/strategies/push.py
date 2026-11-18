from __future__ import annotations
import random
import simpy
from ..common.models import StatusList, VerificationAttempt, NodeStats
from ..common.issuer import Issuer

class PushNode:
    def __init__(
        self,
        node_id: int,
        env: simpy.Environment,
        issuer: Issuer,
        is_online: bool,
        rng: random.Random,
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
        self.awareness_times: dict[int, float] = {}

        env.process(self._connectivity_process())
        env.process(self._verify_process())

        # If initially online, receive a push immediately (unless dead)
        if is_online and not is_dead:
            issuer.notify_online(self)

    # Randomly toggles online/offline with the given mean time between switches.
    # On coming online, the node is sent the latest StatusList so it can compare versions.
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

                # Node just came online: the issuer pushes immediately (unless dead)
                if not self.is_dead:
                    self.issuer.notify_online(self)

    # Receive a push from the issuer
    def receive_push(self, status_list: StatusList) -> None:
        current_version = self.cached_list.version if self.cached_list is not None else -1
        if status_list.version <= current_version:
            return  # older or equal: nothing to update

        prev_revoked = (
            set(self.cached_list.revoked_ids) if self.cached_list is not None else set()
        )

        self.cached_list = status_list
        bytes_rx = status_list.byte_size()
        self.stats.bytes_transferred += bytes_rx
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, bytes_rx)

        # The list is newer: record awareness_times[cred_id] = sim_time for every newly revoked credential.
        newly_known = set(status_list.revoked_ids) - prev_revoked
        for cid in newly_known:
            if cid not in self.awareness_times:
                self.awareness_times[cid] = self.env.now

    # Periodically verifies a credential to measure the false acceptance rate.
    # Identical to PullNode: only the distribution mechanism is being compared, not the verification logic.
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

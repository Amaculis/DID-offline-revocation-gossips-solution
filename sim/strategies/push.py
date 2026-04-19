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
        mean_online_duration: float = 7200,   # 2h
        mean_offline_duration: float = 1800,  # 30min
    ):
        self.node_id = node_id
        self.env = env
        self.issuer = issuer
        self.rng = rng
        self.mean_online = mean_online_duration
        self.mean_offline = mean_offline_duration

        self.is_online = is_online
        self.cached_list: StatusList | None = None
        self.stats = NodeStats(node_id=node_id)
        self.verification_log: list[VerificationAttempt] = []
        self.awareness_times: dict[int, float] = {}

        env.process(self._connectivity_process())
        env.process(self._verify_process())

        # Ja sākotnēji ir tiešsaistē, saņem uzreiz push
        if is_online:
            issuer.notify_online(self)

    # ------------------------------------------------------------------
    # Nejauši pārliek online vai offline ar noteiktu vidējo laiku starp pārslēgumiem. Kad parādās online, tas tiek informēts par jaunāko StatusList, lai varētu salīdzināt versijas un izlemt, vai pieņemt jauno sarakstu.
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
                
                # Node tikko parādījās online — izdevējs tūlītēji push
                self.issuer.notify_online(self)

    # ------------------------------------------------------------------
    # Saņem push no izdevēja
    # ------------------------------------------------------------------
    def receive_push(self, status_list: StatusList) -> None:
        """Accept the pushed list only if it carries a strictly newer version."""
        current_version = self.cached_list.version if self.cached_list is not None else -1
        if status_list.version <= current_version:
            return  # ja mazāks vai vienāds, tad nevajag atjaunināt

        prev_revoked = (
            set(self.cached_list.revoked_ids) if self.cached_list is not None else set()
        )

        self.cached_list = status_list
        bytes_rx = status_list.byte_size()
        self.stats.bytes_transferred += bytes_rx
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, bytes_rx)

        # Ja saraksts ir jaunāks, tad pārbauda, kuras revokācijas ir jaunas (nav prev_revoked), un ieraksta awareness_times[cred_id] = sim_time.
        newly_known = set(status_list.revoked_ids) - prev_revoked
        for cid in newly_known:
            if cid not in self.awareness_times:
                self.awareness_times[cid] = self.env.now

    # ------------------------------------------------------------------
    # Periodiski pārbauda akreditācijas statusu, lai izmērītu false acceptance rate. Šī daļa ir identiska PullNode, jo mēs vēlamies salīdzināt tikai izplatīšanās mehānismu, nevis verifikācijas loģiku.
    # ------------------------------------------------------------------
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

from __future__ import annotations
import random
import simpy
from ..common.models import StatusList, VerificationAttempt, NodeStats
from ..common.issuer import Issuer


# ---------------------------------------------------------------------------
# PushHolderGossipNode (verifier)
# ---------------------------------------------------------------------------

class PushHolderGossipNode:

    _REFRESH_CHECK = 300  # seconds between TTL-expiry checks (fallback pull)

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

        self.peers: list[PushHolderGossipNode] = []
        self.holders: list[PushHolderNode] = []

        # Šis fetch tiek veikts bez apmaksas, jo tas ir nepieciešams, lai nodrošinātu, ka vismaz viens mezgls sāk ar jaunāko sarakstu, un tāpēc var izplatīt to pārējiem caur gossip.
        self._initial_fetch()

        # Ja sākotnēji ir tiešsaistē, saņem uzreiz push (tikai ja nav dead)
        if is_online and not is_dead:
            issuer.notify_online(self)

        env.process(self._connectivity_process())
        env.process(self._refresh_process())
        env.process(self._gossip_process())
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
                # Ja sākotnēji ir tiešsaistē, saņem uzreiz push (tikai ja nav dead)
                if not self.is_dead:
                    self.issuer.notify_online(self)

    def _refresh_process(self):
        #Atkārtoti pārbauda, vai saraksts ir novecojis, un ja jā, tad atjauno to no izdevēja. Tas kalpo kā rezerves mehānisms, lai nodrošinātu, ka mezgls galu galā saņem jaunu sarakstu, pat ja push tika palaists garām (piemēram, ja mezgls bija offline īsi pirms push un palika offline īsi pēc push).
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

    def _gossip_process(self):
        while True:
            delay = self.rng.expovariate(self.contact_rate)
            yield self.env.timeout(delay)

            if not self.is_online:
                self.stats.stale_hits += 1
                continue
            if not self.peers:
                continue

            peer: PushHolderGossipNode = self.rng.choice(self.peers)
            if not peer.is_online and not peer.is_dead:
                continue

            self_ver = self.cached_list.version if self.cached_list else -1
            peer_ver = peer.cached_list.version if peer.cached_list else -1

            if self_ver > peer_ver:
                self._transfer_to(peer)
            elif peer_ver > self_ver:
                peer._transfer_to(self)

    def _transfer_to(self, peer: PushHolderGossipNode):
        peer.receive_gossip(self.cached_list)
        self.stats.bytes_transferred += self.cached_list.byte_size()

    def receive_push(self, new_list: StatusList) -> None:
        #Pieņem push no izdevēja
        self._absorb(new_list)

    def receive_gossip(self, new_list: StatusList) -> None:
        self._absorb(new_list)

    def receive_holder_list(self, new_list: StatusList) -> None:
        #Pieņem push no holdera, ar kuru notiek prezentācija
        self._absorb(new_list)

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

    def _verify_process(self):
        mean_verify_interval = 3600
        while True:
            delay = self.rng.expovariate(1 / mean_verify_interval)
            yield self.env.timeout(delay)
            #if self.is_online:
            #    self._do_verify()
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

    def _do_verify_holder(self, holder: PushHolderNode):
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


# ---------------------------------------------------------------------------
# PushHolderNode (credential holder)
# ---------------------------------------------------------------------------

class PushHolderNode:
    """Credential holder — identical to HolderNode; no Issuer access."""

    def __init__(
        self,
        node_id: int,
        env: simpy.Environment,
        issuer: Issuer,
        is_online: bool,
        rng: random.Random,
        mean_online_duration: float = 3600,
        mean_offline_duration: float = 14400,
        mean_presentation_interval: float = 7200,
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
        self.cached_list: StatusList | None = None
        self.stats = NodeStats(node_id=node_id)
        self.verification_log: list[VerificationAttempt] = []
        self.awareness_times: dict[int, float] = {}

        self.verifiers: list[PushHolderGossipNode] = []
        self.is_holder = True

        env.process(self._connectivity_process())
        env.process(self._presentation_process())

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

    def _presentation_process(self):
        while True:
            delay = self.rng.expovariate(1 / self.mean_presentation_interval)
            yield self.env.timeout(delay)

            if not self.is_online or not self.verifiers:
                continue
            verifier = self.rng.choice(self.verifiers)
            if not verifier.is_online:
                continue

            self._exchange_list(verifier)
            verifier._do_verify_holder(self)

    def _exchange_list(self, verifier: PushHolderGossipNode):
        holder_ver = self.cached_list.version if self.cached_list else -1
        verifier_ver = verifier.cached_list.version if verifier.cached_list else -1

        if holder_ver > verifier_ver:
            if self.cached_list and not self.cached_list.is_expired(self.env.now):
                size = self.cached_list.byte_size()
                self.stats.bytes_transferred += size
                verifier.receive_holder_list(self.cached_list)
        elif verifier_ver > holder_ver:
            if verifier.cached_list:
                size = verifier.cached_list.byte_size()
                verifier.stats.bytes_transferred += size
                self._accept_list(verifier.cached_list)

    def _accept_list(self, new_list: StatusList):
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
            self.awareness_times.setdefault(cid, self.env.now)

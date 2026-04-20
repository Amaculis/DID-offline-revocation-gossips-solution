"""GOSSIP strategy: nodes exchange StatusLists when they randomly meet."""
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
        offline_ratio: float,
        mean_online_duration: float = 7200,   # 2h
        mean_offline_duration: float = 1800,  # 30min
        contact_rate: float = 1 / 600,        # vidējais laiks starp kontaktiem ar citiem mezgliem (sekundēs simulaācijas laikā)
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

        # Pēc node izveides, simulaācijas izpildītājs piepilda šo sarakstu ar atsaucēm uz kaimiņu mezgliem, pamatojoties uz grafu topoloģiju.
        self.peers: list[GossipNode] = []

        # Paņem sākotnējo sarakstu no izdevēja, lai versiju salīdzināšana darbotos
        self._initial_fetch()

        env.process(self._connectivity_process())
        env.process(self._refresh_process())
        env.process(self._gossip_process())
        env.process(self._verify_process())

    # ------------------------------------------------------------------
    # Paņem sākotnējo sarakstu no izdevēja, lai versiju salīdzināšana darbotos. Šis fetch tiek veikts bez apmaksas, jo tas ir nepieciešams, lai nodrošinātu, ka vismaz viens mezgls sāk ar jaunāko sarakstu, un tāpēc var izplatīt to pārējiem caur gossip.
    # ------------------------------------------------------------------
    def _initial_fetch(self):
        fresh = self.issuer.current_list
        self.cached_list = fresh
        bytes_rx = fresh.byte_size()
        self.stats.bytes_transferred += bytes_rx
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, bytes_rx)
        for cid in fresh.revoked_ids:
            self.awareness_times.setdefault(cid, self.env.now)

    # ------------------------------------------------------------------
    # Savienojamība vienāda ar Pull 
    # ------------------------------------------------------------------
    def _connectivity_process(self):
        if self.is_dead:
            return  # permanently offline — never toggles
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
    # TTL atjaunināšana: iegūst svaigus datus no izdevēja, 
    # kad kešatmiņa ir novecojusi. 
    # Gossip vien var izplatīt tikai to, 
    # ko kāds mezgls jau ir paņēmis; 
    # šis process nodrošina, 
    # ka vismaz viens mezgls paņem jaunāko versiju, 
    # un pēc tam gossip tīkls to izplata peer-to-peer.
    # ------------------------------------------------------------------
    _REFRESH_CHECK = 300  # check every 5 sim-minutes

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

    # ------------------------------------------------------------------
    # Nejauši satiekoties, ja abi ir online, 
    # salīdzina sarakstu versijas un pārsūta jaunāko uz otru pusi. 
    # Ja viens no mezgliem ir offline, 
    # tad nav nekādas mijiedarbības. 
    # Ja mezgls ir online, bet tam nav neviena peer, 
    # tad tas vienkārši gaida nākamo tikšanos.
    # ------------------------------------------------------------------
    def _gossip_process(self):
        while True:
            delay = self.rng.expovariate(self.contact_rate)
            yield self.env.timeout(delay)

            if not self.is_online:
                self.stats.stale_hits += 1
                continue

            if not self.peers:
                continue

            peer: GossipNode = self.rng.choice(self.peers)
            if not peer.is_online and not peer.is_dead:
                continue

            # salīdzina versijas, lai pārbaudītu saraksta derīgumu un izvairītos no saņemšanas vai izplatīšanas vecāku sarakstu (kas varētu būt ļaunprātīgi vai vienkārši nevēlamas novecojušas informācijas avots).
            self_ver = self.cached_list.version if self.cached_list else -1
            peer_ver = peer.cached_list.version if peer.cached_list else -1

            if self_ver > peer_ver:
                self._transfer_to(peer)
            elif peer_ver > self_ver:
                peer._transfer_to(self)
            # Ja versijas ir vienādas, tad nav ko darīt, jo tas nozīmē, ka abi mezgli jau zina par visām revokācijām, kas ir iekļautas šajā versijā. Nav nepieciešams izplatīt sarakstu, jo tas nesatur nekādu jaunu informāciju nevienam no mezgliem.

    def _transfer_to(self, peer: GossipNode):
        
        peer.receive_gossip(self.cached_list)
        size = self.cached_list.byte_size()
        self.stats.bytes_transferred += size  # sūtītājs maksā par upload, saņēmējs maksā par download, kopējais ir 2*size, bet mēs uzskaitām atsevišķi, lai varētu analizēt upload vs download


    def receive_gossip(self, new_list: StatusList) -> None:
        if new_list is None:
            return
        current_ver = self.cached_list.version if self.cached_list else -1
        if new_list.version <= current_ver:
            return   # Ja jaunā versija nav lielāka par esošo, tad noraida, jo tas varētu būt ļaunprātīgs mēģinājums nosūtīt vecāku sarakstu, kas varētu saturēt novecojušu informāciju. Gossip mehānisms pieņem tikai jaunākus sarakstus, lai nodrošinātu, ka informācija izplatās tikai uz priekšu un nekad atpakaļ, kas palīdz aizsargāt pret ļaunprātīgu datu injekciju.

        prev_revoked = set(self.cached_list.revoked_ids) if self.cached_list else set()

        self.cached_list = new_list
        size = new_list.byte_size()
        self.stats.bytes_transferred += size  # Sāņēmējs maksā par lejuplādi
        self.stats.fetch_count += 1
        self.stats.max_list_bytes = max(self.stats.max_list_bytes, size)

        newly_known = set(new_list.revoked_ids) - prev_revoked
        for cid in newly_known:
            if cid not in self.awareness_times:
                self.awareness_times[cid] = self.env.now

    # ------------------------------------------------------------------
    # Verifikācijas identiska ar Pull
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

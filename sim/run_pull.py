from __future__ import annotations
import random
import simpy
from .common.issuer import Issuer
from .common.network import build_graph, assign_initial_states, assign_dead_nodes
from .strategies.pull import PullNode
from .common.metrics import summarize


def run(
    network_size: int = 500,
    offline_ratio: float = 0.2,
    dead_ratio: float = 0.0,
    ttl: float = 3600,
    revocation_rate: float = 0.01,
    sim_duration: float = 86400 * 7,
    seed: int = 42,
) -> dict:
    rng = random.Random(seed)
    env = simpy.Environment()

    num_credentials = network_size * 10  # 10 credentials per node on average

    issuer = Issuer(
        env=env,
        revocation_rate=revocation_rate,
        ttl=ttl,
        num_credentials=num_credentials,
        rng=random.Random(rng.randint(0, 2**31)),
    )

    graph = build_graph(network_size, seed=seed)
    dead = assign_dead_nodes(network_size, dead_ratio, rng)
    online_states = assign_initial_states(network_size, offline_ratio, rng, dead_nodes=dead)

    nodes: list[PullNode] = []
    for node_id in range(network_size):
        node = PullNode(
            node_id=node_id,
            env=env,
            issuer=issuer,
            is_online=online_states[node_id],
            rng=random.Random(rng.randint(0, 2**31)),
            offline_ratio=offline_ratio,
            is_dead=(node_id in dead),
        )
        nodes.append(node)

    # patch node lai izsekotu, kad katrs mezgls pirmo reizi uzzina par katru revokāciju, lai varētu aprēķināt izplatīšanās aizkavi.
    _patch_awareness_tracking(nodes, issuer)

    env.run(until=sim_duration)

    stats = [n.stats for n in nodes]
    result = summarize(issuer.revocation_log, nodes, stats, ttl=ttl)
    result["strategy"] = "PULL"
    result["network_size"] = network_size
    result["offline_ratio"] = offline_ratio
    result["ttl_s"] = ttl
    result["revocation_rate"] = revocation_rate
    return result


def _patch_awareness_tracking(nodes: list[PullNode], issuer: Issuer):

    """
    Monkey-patch katra mezgla _fetch(), lai ierakstītu, kad tas pirmo reizi uzzina par katru revokāciju. awareness_times[cred_id] = sim_time.
     Tas ļauj aprēķināt izplatīšanās aizkavi katrai revokācijai un katram mezglam, un pēc tam apkopot šos datus, lai iegūtu izplatīšanās aizkavi p95 un vidējo vērtību. 
    """


    for node in nodes:
        node.awareness_times: dict[int, float] = {}
        original_fetch = node._fetch.__func__  # unbound

        def make_patched(n, orig):
            def patched_fetch(self=n):
                prev_revoked = (
                    set(self.cached_list.revoked_ids)
                    if self.cached_list is not None
                    else set()
                )
                orig(self)  # call original
                new_revoked = set(self.cached_list.revoked_ids)
                newly_known = new_revoked - prev_revoked
                for cid in newly_known:
                    if cid not in self.awareness_times:
                        self.awareness_times[cid] = self.env.now
            return patched_fetch

        import types
        node._fetch = types.MethodType(make_patched(node, original_fetch), node)

from __future__ import annotations
import random
import simpy
from .common.issuer import Issuer
from .common.network import build_graph, assign_initial_states, assign_dead_nodes
from .strategies.push import PushNode
from .common.metrics import summarize


def run(
    network_size: int = 500,
    offline_ratio: float = 0.2,
    dead_ratio: float = 0.0,
    ttl: float = 3600,
    revocation_rate: float = 0.01,
    sim_duration: float = 86400 * 7,
    seed: int = 42,
    verificatior_ratio: float = 0.7, # šis lai nobalansētu HOLDER-GOSSIP
) -> dict:
    rng = random.Random(seed)
    env = simpy.Environment()
    #network_size = int(network_size * verificatior_ratio)
    print(f"ver_rate = {verificatior_ratio}")

    num_credentials = network_size * 10
    n_verifiers = int(network_size * verificatior_ratio)


    issuer = Issuer(
        env=env,
        revocation_rate=revocation_rate,
        ttl=ttl,
        num_credentials=num_credentials,
        rng=random.Random(rng.randint(0, 2**31)),
    )

    build_graph(n_verifiers, seed=seed)
    dead = assign_dead_nodes(n_verifiers, dead_ratio, rng)
    online_states = assign_initial_states(n_verifiers, offline_ratio, rng, dead_nodes=dead)

    nodes: list[PushNode] = []
    for node_id in range(n_verifiers):
        node = PushNode(
            node_id=node_id,
            env=env,
            issuer=issuer,
            is_online=online_states[node_id],
            rng=random.Random(rng.randint(0, 2**31)),
            is_dead=(node_id in dead),
        )
        nodes.append(node)
        issuer.register(node)

    env.run(until=sim_duration)

    stats = [n.stats for n in nodes]
    result = summarize(issuer.revocation_log, nodes, stats, ttl=ttl)
    result["strategy"] = "PUSH"
    result["network_size"] = network_size
    result["offline_ratio"] = offline_ratio
    result["ttl_s"] = ttl
    result["revocation_rate"] = revocation_rate
    return result

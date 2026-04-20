from __future__ import annotations
import random
import simpy
from .common.issuer import Issuer
from .common.network import build_graph, assign_initial_states, assign_dead_nodes
from .strategies.gossip import GossipNode
from .common.metrics import summarize


def run(
    network_size: int = 500,
    offline_ratio: float = 0.2,
    dead_ratio: float = 0.0,
    ttl: float = 3600,
    revocation_rate: float = 0.01,
    sim_duration: float = 86400 * 7,
    seed: int = 42,
    contact_rate: float = 1 / 600,
) -> dict:
    rng = random.Random(seed)
    env = simpy.Environment()

    num_credentials = network_size * 10

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

    nodes: list[GossipNode] = []
    for node_id in range(network_size):
        node = GossipNode(
            node_id=node_id,
            env=env,
            issuer=issuer,
            is_online=online_states[node_id],
            rng=random.Random(rng.randint(0, 2**31)),
            offline_ratio=offline_ratio,
            contact_rate=contact_rate,
            is_dead=(node_id in dead),
        )
        nodes.append(node)

    # Peer to peer mezglus apmaiņas saskaņā ar grafu topoloģiju
    for node_id, node in enumerate(nodes):
        node.peers = [nodes[nbr] for nbr in graph.neighbors(node_id)]

    env.run(until=sim_duration)

    stats = [n.stats for n in nodes]
    result = summarize(issuer.revocation_log, nodes, stats, ttl=ttl)
    result["strategy"] = "GOSSIP"
    result["network_size"] = network_size
    result["offline_ratio"] = offline_ratio
    result["ttl_s"] = ttl
    result["revocation_rate"] = revocation_rate
    return result

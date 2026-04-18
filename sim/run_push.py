from __future__ import annotations
import random
import simpy
from .issuer import Issuer
from .network import build_graph, assign_initial_states
from .strategies.push import PushNode
from .metrics import summarize


def run(
    network_size: int = 500,
    offline_ratio: float = 0.2,
    ttl: float = 3600,
    revocation_rate: float = 0.01,
    sim_duration: float = 86400 * 7,
    seed: int = 42,
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

    build_graph(network_size, seed=seed)  # Atstāts, lai saglabātu topoloģijas vienādību ar citiem skrējieniem
    online_states = assign_initial_states(network_size, offline_ratio, rng)

    nodes: list[PushNode] = []
    for node_id in range(network_size):
        node = PushNode(
            node_id=node_id,
            env=env,
            issuer=issuer,
            is_online=online_states[node_id],
            rng=random.Random(rng.randint(0, 2**31)),
        )
        nodes.append(node)

    env.run(until=sim_duration)

    stats = [n.stats for n in nodes]
    result = summarize(issuer.revocation_log, nodes, stats)
    result["strategy"] = "PUSH"
    result["network_size"] = network_size
    result["offline_ratio"] = offline_ratio
    result["ttl_s"] = ttl
    result["revocation_rate"] = revocation_rate
    return result

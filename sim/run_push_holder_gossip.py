
from __future__ import annotations
import random
import simpy
from .common.issuer import Issuer
from .common.network import build_graph, assign_initial_states, assign_dead_nodes
from .strategies.push_holder_gossip import PushHolderGossipNode, PushHolderNode
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
    holder_ratio: float = 0.3,
    mean_presentation_interval: float = 7200,
    mean_online_duration: float = 3600,
    mean_offline_duration: float = 14400,
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

    n_verifiers = network_size
    n_holders = int(network_size * holder_ratio)

    graph = build_graph(n_verifiers, seed=seed)
    dead = assign_dead_nodes(network_size, dead_ratio, rng)
    dead_verifiers = {n for n in dead if n < n_verifiers}
    dead_holders = {n - n_verifiers for n in dead if n >= n_verifiers}

    verifier_online = assign_initial_states(n_verifiers, offline_ratio, rng, dead_nodes=dead_verifiers)
    holder_online = assign_initial_states(n_holders, offline_ratio, rng, dead_nodes=dead_holders)

    
    verifiers: list[PushHolderGossipNode] = []
    for vid in range(n_verifiers):
        node = PushHolderGossipNode(
            node_id=vid,
            env=env,
            issuer=issuer,
            is_online=verifier_online[vid],
            rng=random.Random(rng.randint(0, 2**31)),
            offline_ratio=offline_ratio,
            mean_online_duration=mean_online_duration,
            mean_offline_duration=mean_offline_duration,
            contact_rate=contact_rate,
            is_dead=(vid in dead_verifiers),
        )
        verifiers.append(node)
        issuer.register(node)

   
    for vid, verifier in enumerate(verifiers):
        verifier.peers = [verifiers[nbr] for nbr in graph.neighbors(vid)]

    
    holders: list[PushHolderNode] = []
    for hid in range(n_holders):
        node = PushHolderNode(
            node_id=n_verifiers + hid,
            env=env,
            issuer=issuer,
            is_online=holder_online[hid],
            rng=random.Random(rng.randint(0, 2**31)),
            mean_online_duration=mean_online_duration,
            mean_offline_duration=mean_offline_duration,
            mean_presentation_interval=mean_presentation_interval,
            is_dead=(hid in dead_holders),
        )
        holders.append(node)

    for holder in holders:
        holder.verifiers = verifiers

    all_nodes = verifiers + holders
    env.run(until=sim_duration)

    stats = [n.stats for n in all_nodes]
    result = summarize(issuer.revocation_log, all_nodes, stats, ttl=ttl)
    result["strategy"] = "PUSH-HOLDER-GOSSIP"
    result["network_size"] = network_size
    result["offline_ratio"] = offline_ratio
    result["ttl_s"] = ttl
    result["revocation_rate"] = revocation_rate
    return result

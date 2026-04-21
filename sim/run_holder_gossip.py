"""Run the HOLDER-GOSSIP strategy simulation and return a summary dict."""
from __future__ import annotations
import random
import simpy
from .common.issuer import Issuer
from .common.network import build_graph, assign_initial_states, assign_dead_nodes
from .strategies.holder_gossip import HolderGossipNode, HolderNode
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

    n_verifiers = int(network_size * (1 - holder_ratio))
    n_holders = network_size - n_verifiers

    # Topology and initial states for verifiers
    graph = build_graph(n_verifiers, seed=seed)
    dead = assign_dead_nodes(network_size, dead_ratio, rng)
    dead_verifiers = {n for n in dead if n < n_verifiers}
    dead_holders = {n - n_verifiers for n in dead if n >= n_verifiers}

    verifier_online = assign_initial_states(n_verifiers, offline_ratio, rng, dead_nodes=dead_verifiers)
    holder_online = assign_initial_states(n_holders, offline_ratio, rng, dead_nodes=dead_holders)

    # Create verifiers
    verifiers: list[HolderGossipNode] = []
    for vid in range(n_verifiers):
        node = HolderGossipNode(
            node_id=vid,
            env=env,
            issuer=issuer,
            is_online=verifier_online[vid],
            rng=random.Random(rng.randint(0, 2**31)),
            offline_ratio=offline_ratio,
            contact_rate=contact_rate,
            is_dead=(vid in dead_verifiers),
        )
        verifiers.append(node)

    # Wire verifier↔verifier gossip peers from graph topology
    for vid, verifier in enumerate(verifiers):
        verifier.peers = [verifiers[nbr] for nbr in graph.neighbors(vid)]

    # Create holders
    holders: list[HolderNode] = []
    for hid in range(n_holders):
        node = HolderNode(
            node_id=n_verifiers + hid,  # unique node_id across all nodes
            env=env,
            issuer=issuer,
            is_online=holder_online[hid],
            rng=random.Random(rng.randint(0, 2**31)),
            mean_presentation_interval=mean_presentation_interval,
            is_dead=(hid in dead_holders),
        )
        holders.append(node)

    # Wire each holder to a random local neighbourhood of verifiers (~6 neighbours)
    for holder in holders:
        k = min(6, len(verifiers))
        holder.verifiers = rng.sample(verifiers, k)

    all_nodes = verifiers + holders
    env.run(until=sim_duration)

    stats = [n.stats for n in all_nodes]
    result = summarize(issuer.revocation_log, all_nodes, stats, ttl=ttl)
    result["strategy"] = "HOLDER-GOSSIP"
    result["network_size"] = network_size
    result["offline_ratio"] = offline_ratio
    result["ttl_s"] = ttl
    result["revocation_rate"] = revocation_rate
    return result

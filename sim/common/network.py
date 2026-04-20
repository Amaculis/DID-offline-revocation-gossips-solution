from __future__ import annotations
import random
import networkx as nx


def build_graph(network_size: int, seed: int = 42) -> nx.Graph:
    p = 6 / (network_size - 1)
    return nx.erdos_renyi_graph(network_size, p, seed=seed)


def assign_initial_states(
    network_size: int,
    offline_ratio: float,
    rng: random.Random,
    dead_nodes: set[int] | None = None,
) -> list[bool]:
    """online=True, offline=False. Dead nodes are always False."""
    dead = dead_nodes or set()
    candidate_pool = [n for n in range(network_size) if n not in dead]
    offline_count = int(network_size * offline_ratio)
    offline_count = min(offline_count, len(candidate_pool))
    offline_nodes = set(rng.sample(candidate_pool, offline_count))
    return [False if (n in dead or n in offline_nodes) else True
            for n in range(network_size)]


def assign_dead_nodes(
    network_size: int,
    dead_ratio: float,
    rng: random.Random,
) -> set[int]:
    """Return the set of node IDs that are permanently offline."""
    dead_count = int(network_size * dead_ratio)
    return set(rng.sample(range(network_size), dead_count))

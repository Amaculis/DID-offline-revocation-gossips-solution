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
) -> list[bool]:
    states = [True] * network_size
    offline_count = int(network_size * offline_ratio)
    offline_nodes = rng.sample(range(network_size), offline_count)
    for n in offline_nodes:
        states[n] = False
    return states

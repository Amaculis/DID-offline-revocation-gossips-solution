"""Shared fixtures for the DID offline-revocation test suite."""
from __future__ import annotations
import random
import pytest
import simpy

from sim.issuer import Issuer
from sim.strategies.pull import PullNode
from sim.run_pull import run as pull_run, _patch_awareness_tracking
from sim.network import assign_initial_states

# ---------------------------------------------------------------------------
# Low-level building blocks
# ---------------------------------------------------------------------------

@pytest.fixture
def env() -> simpy.Environment:
    return simpy.Environment()


@pytest.fixture
def issuer(env: simpy.Environment) -> Issuer:
    return Issuer(
        env=env,
        revocation_rate=0.01,
        ttl=600.0,
        num_credentials=100,
        rng=random.Random(0),
    )


# ---------------------------------------------------------------------------
# Integration fixture: 10-node PULL run for 7200 s
# ---------------------------------------------------------------------------

_SMALL_SIM = dict(
    seed=42,
    network_size=10,
    sim_duration=7200,
    ttl=600.0,
    offline_ratio=0.2,
    revocation_rate=0.01,
)


@pytest.fixture
def small_pull_nodes():
    """Returns (nodes, issuer) after a 10-node PULL sim for 7200 s."""
    p = _SMALL_SIM
    rng = random.Random(p["seed"])
    env = simpy.Environment()
    iss = Issuer(
        env=env,
        revocation_rate=p["revocation_rate"],
        ttl=p["ttl"],
        num_credentials=p["network_size"] * 10,
        rng=random.Random(rng.randint(0, 2**31)),
    )
    online_states = assign_initial_states(p["network_size"], p["offline_ratio"], rng)
    nodes: list[PullNode] = []
    for nid in range(p["network_size"]):
        node = PullNode(
            node_id=nid,
            env=env,
            issuer=iss,
            is_online=online_states[nid],
            rng=random.Random(rng.randint(0, 2**31)),
            offline_ratio=p["offline_ratio"],
        )
        nodes.append(node)
    _patch_awareness_tracking(nodes, iss)
    env.run(until=p["sim_duration"])
    return nodes, iss


@pytest.fixture
def small_pull_run():
    """Returns the metrics dict from run_pull.run() with small-sim parameters."""
    p = _SMALL_SIM
    return pull_run(
        network_size=p["network_size"],
        offline_ratio=p["offline_ratio"],
        ttl=p["ttl"],
        revocation_rate=p["revocation_rate"],
        sim_duration=p["sim_duration"],
        seed=p["seed"],
    )

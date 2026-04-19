"""Layer 3 — Unit tests for sim.issuer.Issuer."""
from __future__ import annotations
import random
import simpy
import pytest
from sim.common.issuer import Issuer


def _make(
    *,
    rate: float = 0.01,
    ttl: float = 600.0,
    credentials: int = 100,
    seed: int = 0,
) -> tuple[simpy.Environment, Issuer]:
    env = simpy.Environment()
    iss = Issuer(env=env, revocation_rate=rate, ttl=ttl,
                 num_credentials=credentials, rng=random.Random(seed))
    return env, iss


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

class TestIssuerInitialState:

    def test_initial_version_is_one(self):
        _, iss = _make()
        assert iss.current_list.version == 1

    def test_initial_revocation_log_empty(self):
        _, iss = _make()
        assert iss.revocation_log == []

    def test_initial_revoked_ids_empty(self):
        _, iss = _make()
        assert len(iss.current_list.revoked_ids) == 0

    def test_credentials_list_length(self):
        _, iss = _make(credentials=50)
        assert len(iss.credentials) == 50

    def test_ttl_on_current_list(self):
        _, iss = _make(ttl=300.0)
        assert iss.current_list.ttl == 300.0


# ---------------------------------------------------------------------------
# Revocation count and version invariant
# ---------------------------------------------------------------------------

class TestIssuerRevocations:

    def test_version_equals_revocations_plus_one(self):
        env, iss = _make(rate=0.5, credentials=500, seed=1)
        env.run(until=50.0)
        assert iss.current_list.version == len(iss.revocation_log) + 1

    def test_no_duplicate_credential_revocations(self):
        env, iss = _make(rate=0.5, credentials=200, seed=3)
        env.run(until=200.0)
        revoked = [e.credential_id for e in iss.revocation_log]
        assert len(revoked) == len(set(revoked))

    def test_zero_revocations_at_time_zero(self):
        # Don't call env.run() — SimPy raises if until <= env.now (0)
        _, iss = _make(rate=10.0)
        assert len(iss.revocation_log) == 0

    def test_revocation_count_within_statistical_bounds(self):
        # rate=1.0, duration=100s → Poisson mean=100; loose bound [50, 200]
        env, iss = _make(rate=1.0, credentials=1000, seed=0)
        env.run(until=100.0)
        n = len(iss.revocation_log)
        assert 50 <= n <= 200, f"Expected ~100 revocations, got {n}"

    def test_exact_deterministic_count(self):
        # Pin exact output for seed=0, rate=1.0, 100s — catches RNG regressions
        env, iss = _make(rate=1.0, credentials=1000, seed=0)
        env.run(until=100.0)
        assert len(iss.revocation_log) == 105


# ---------------------------------------------------------------------------
# is_revoked() ground truth
# ---------------------------------------------------------------------------

class TestIssuerIsRevoked:

    def test_revoked_credentials_detected(self):
        env, iss = _make(rate=1.0, credentials=1000, seed=0)
        env.run(until=10.0)
        for event in iss.revocation_log:
            assert iss.is_revoked(event.credential_id)

    def test_non_revoked_credentials_pass(self):
        env, iss = _make(rate=1.0, credentials=1000, seed=0)
        env.run(until=10.0)
        revoked_set = {e.credential_id for e in iss.revocation_log}
        non_revoked = [c for c in iss.credentials if c not in revoked_set][:20]
        for cid in non_revoked:
            assert not iss.is_revoked(cid)

    def test_is_revoked_agrees_with_current_list(self):
        env, iss = _make(rate=0.5, credentials=200, seed=7)
        env.run(until=50.0)
        for cid in iss.credentials:
            assert iss.is_revoked(cid) == (cid in iss.current_list.revoked_ids)


# ---------------------------------------------------------------------------
# Timestamp correctness
# ---------------------------------------------------------------------------

def test_current_list_issued_at_matches_last_event():
    env, iss = _make(rate=0.5, credentials=200, seed=2)
    env.run(until=200.0)
    if iss.revocation_log:
        assert iss.current_list.issued_at == iss.revocation_log[-1].revoked_at

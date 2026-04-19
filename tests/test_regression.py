"""Layer 5 — Regression / golden-output tests for run_pull.run().

Parameters: seed=42, network_size=50, sim_duration=86400 s, ttl=3600 s.
Golden values verified by running the simulation on 2026-04-16.
"""
from __future__ import annotations
import pytest
from sim.run_pull import run as pull_run


@pytest.fixture(scope="module")
def regression_run():
    """Runs once per session — ~3 s wall time."""
    return pull_run(
        network_size=50,
        offline_ratio=0.2,
        ttl=3600.0,
        revocation_rate=0.01,
        sim_duration=86400,
        seed=42,
    )


# ---------------------------------------------------------------------------
# Exact golden values
# ---------------------------------------------------------------------------

class TestRegressionGoldenValues:

    def test_propagation_delay_p95(self, regression_run):
        assert regression_run["propagation_delay_p95_s"] == pytest.approx(
            6526.121849882002, rel=1e-6
        )

    def test_propagation_delay_mean(self, regression_run):
        assert regression_run["propagation_delay_mean_s"] == pytest.approx(
            4515.855080129863, rel=1e-6
        )

    def test_false_acceptance_rate(self, regression_run):
        assert regression_run["false_acceptance_rate"] == pytest.approx(
            0.030927835051546393, rel=1e-6
        )

    def test_total_verifications(self, regression_run):
        assert regression_run["total_verifications"] == 1224

    def test_total_revocations(self, regression_run):
        assert regression_run["total_revocations"] == 500

    def test_revocations_reached_95pct(self, regression_run):
        assert regression_run["revocations_reached_95pct"] == 500

    def test_bandwidth_mean(self, regression_run):
        assert regression_run["bandwidth"]["mean"] == pytest.approx(201023.68, rel=1e-6)

    def test_bandwidth_total(self, regression_run):
        assert int(regression_run["bandwidth"]["total"]) == 10_051_184

    def test_storage_mean(self, regression_run):
        assert regression_run["storage"]["mean"] == pytest.approx(2064.0, rel=1e-6)

    def test_storage_max(self, regression_run):
        assert int(regression_run["storage"]["max"]) == 2064

    def test_strategy_tag(self, regression_run):
        assert regression_run["strategy"] == "PULL"


# ---------------------------------------------------------------------------
# Sanity bounds (independent of exact golden values)
# ---------------------------------------------------------------------------

class TestRegressionSanityBounds:

    def test_far_low_for_pull(self, regression_run):
        assert regression_run["false_acceptance_rate"] < 0.05

    def test_all_revocations_reached_95pct(self, regression_run):
        assert (
            regression_run["revocations_reached_95pct"]
            == regression_run["total_revocations"]
        )

    def test_p95_within_2ttl(self, regression_run):
        ttl = regression_run["ttl_s"]
        p95 = regression_run["propagation_delay_p95_s"]
        assert p95 <= 2 * ttl, f"p95={p95:.1f} exceeds 2*TTL={2*ttl}"

    def test_bandwidth_positive(self, regression_run):
        assert regression_run["bandwidth"]["mean"] > 0

    def test_storage_max_matches_byte_size_formula(self, regression_run):
        # byte_size = 64 + 4 * total_revocations
        expected = 64 + 4 * regression_run["total_revocations"]
        assert int(regression_run["storage"]["max"]) == expected

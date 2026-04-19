"""Layer 4 — Integration tests for the PULL strategy.

Fixtures from conftest: small_pull_nodes, small_pull_run
  seed=42, network_size=10, sim_duration=7200 s, ttl=600 s
"""
from __future__ import annotations
import pytest
from sim.metrics import propagation_delay, false_acceptance_rate

TTL = 600.0
SIM_DURATION = 7200
CHECK_INTERVAL = 300  # from pull.py


# ---------------------------------------------------------------------------
# Per-node structural checks
# ---------------------------------------------------------------------------

class TestPullNodeBehaviour:

    def test_all_nodes_fetched_at_least_once(self, small_pull_nodes):
        nodes, _ = small_pull_nodes
        for node in nodes:
            assert node.stats.fetch_count > 0, f"Node {node.node_id} never fetched"

    def test_all_nodes_have_positive_bytes_transferred(self, small_pull_nodes):
        nodes, _ = small_pull_nodes
        for node in nodes:
            assert node.stats.bytes_transferred > 0, f"Node {node.node_id}: 0 bytes"

    def test_awareness_times_populated(self, small_pull_nodes):
        nodes, _ = small_pull_nodes
        for node in nodes:
            assert len(node.awareness_times) > 0, f"Node {node.node_id}: empty awareness_times"

    def test_awareness_times_non_negative(self, small_pull_nodes):
        nodes, _ = small_pull_nodes
        for node in nodes:
            for cid, t in node.awareness_times.items():
                assert t >= 0.0

    def test_fetch_count_within_expected_range(self, small_pull_nodes):
        # max feasible: SIM_DURATION / CHECK_INTERVAL = 7200/300 = 24
        nodes, _ = small_pull_nodes
        for node in nodes:
            assert 1 <= node.stats.fetch_count <= 24, (
                f"Node {node.node_id} fetch_count={node.stats.fetch_count}"
            )

    def test_max_list_bytes_at_least_overhead(self, small_pull_nodes):
        nodes, _ = small_pull_nodes
        for node in nodes:
            if node.stats.fetch_count > 0:
                assert node.stats.max_list_bytes >= 64

    def test_verification_log_entries_valid(self, small_pull_nodes):
        nodes, issuer = small_pull_nodes
        for node in nodes:
            for attempt in node.verification_log:
                assert attempt.node_id == node.node_id
                assert attempt.credential_id in issuer.credentials
                assert 0.0 <= attempt.sim_time <= SIM_DURATION
                assert isinstance(attempt.was_revoked, bool)
                assert isinstance(attempt.node_knew, bool)


# ---------------------------------------------------------------------------
# False-acceptance rate
# ---------------------------------------------------------------------------

class TestPullFalseAcceptanceRate:

    def test_far_below_threshold(self, small_pull_run):
        # PULL with TTL=600 s over 7200 s: observed ~0.07 for 10 nodes
        assert small_pull_run["false_acceptance_rate"] < 0.15

    def test_far_non_negative(self, small_pull_run):
        assert small_pull_run["false_acceptance_rate"] >= 0.0

    def test_total_verifications_positive(self, small_pull_run):
        assert small_pull_run["total_verifications"] > 0


# ---------------------------------------------------------------------------
# Propagation delay
# ---------------------------------------------------------------------------

class TestPullPropagationDelay:

    def test_p95_within_2ttl(self, small_pull_nodes):
        nodes, issuer = small_pull_nodes
        delays = propagation_delay(issuer.revocation_log, nodes, target_pct=0.95)
        valid = [d for d in delays.values() if d is not None]
        assert len(valid) > 0, "No credential reached 95% of nodes"
        p95 = sorted(valid)[int(len(valid) * 0.95)]
        assert 0.0 < p95 <= 2 * TTL, f"p95={p95:.1f} outside (0, {2*TTL}]"

    def test_mean_below_ttl(self, small_pull_nodes):
        nodes, issuer = small_pull_nodes
        delays = propagation_delay(issuer.revocation_log, nodes, target_pct=0.95)
        valid = [d for d in delays.values() if d is not None]
        mean = sum(valid) / len(valid)
        assert mean < TTL, f"mean={mean:.1f} should be < TTL={TTL}"

    def test_all_delays_non_negative(self, small_pull_nodes):
        nodes, issuer = small_pull_nodes
        delays = propagation_delay(issuer.revocation_log, nodes, target_pct=0.95)
        for cid, d in delays.items():
            if d is not None:
                assert d >= 0.0, f"Negative delay for cid={cid}"

    def test_awareness_keys_subset_of_revocation_log(self, small_pull_nodes):
        nodes, issuer = small_pull_nodes
        revoked_cids = {e.credential_id for e in issuer.revocation_log}
        for node in nodes:
            stray = set(node.awareness_times.keys()) - revoked_cids
            assert stray == set(), f"Node {node.node_id} has stray awareness_times: {stray}"


# ---------------------------------------------------------------------------
# Result dict shape
# ---------------------------------------------------------------------------

class TestPullRunResultShape:

    _EXPECTED_KEYS = {
        "propagation_delay_p95_s", "propagation_delay_mean_s",
        "revocations_reached_95pct", "total_revocations",
        "false_acceptance_rate", "bandwidth", "storage",
        "total_verifications", "strategy", "network_size",
        "offline_ratio", "ttl_s", "revocation_rate",
    }

    def test_all_expected_keys_present(self, small_pull_run):
        assert self._EXPECTED_KEYS.issubset(small_pull_run.keys())

    def test_strategy_tag(self, small_pull_run):
        assert small_pull_run["strategy"] == "PULL"

    def test_bandwidth_keys(self, small_pull_run):
        assert {"mean", "median", "p95", "total"} <= small_pull_run["bandwidth"].keys()

    def test_storage_keys(self, small_pull_run):
        assert {"mean", "max"} <= small_pull_run["storage"].keys()

    def test_revocations_reached_leq_total(self, small_pull_run):
        assert small_pull_run["revocations_reached_95pct"] <= small_pull_run["total_revocations"]

    def test_total_revocations_positive(self, small_pull_run):
        assert small_pull_run["total_revocations"] > 0

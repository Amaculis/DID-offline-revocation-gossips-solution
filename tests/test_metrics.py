"""Layer 2 — Unit tests for sim.metrics pure functions."""
from __future__ import annotations
import pytest
from sim.models import VerificationAttempt, RevocationEvent
from sim.metrics import false_acceptance_rate, propagation_delay


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _attempt(*, was_revoked: bool, node_knew: bool) -> VerificationAttempt:
    return VerificationAttempt(
        node_id=0, credential_id=1, sim_time=100.0,
        was_revoked=was_revoked, node_knew=node_knew, list_age=10.0,
    )


class _FakeNode:
    def __init__(self, awareness: dict[int, float]):
        self.awareness_times = awareness


def _event(cid: int, revoked_at: float) -> RevocationEvent:
    return RevocationEvent(credential_id=cid, revoked_at=revoked_at)


# ---------------------------------------------------------------------------
# false_acceptance_rate()
# ---------------------------------------------------------------------------

class TestFalseAcceptanceRate:

    def test_empty_list_returns_zero(self):
        assert false_acceptance_rate([]) == 0.0

    def test_no_revoked_credentials_returns_zero(self):
        attempts = [_attempt(was_revoked=False, node_knew=False) for _ in range(5)]
        assert false_acceptance_rate(attempts) == 0.0

    def test_all_revoked_all_known_returns_zero(self):
        attempts = [_attempt(was_revoked=True, node_knew=True) for _ in range(10)]
        assert false_acceptance_rate(attempts) == 0.0

    def test_all_revoked_none_known_returns_one(self):
        attempts = [_attempt(was_revoked=True, node_knew=False) for _ in range(10)]
        assert false_acceptance_rate(attempts) == 1.0

    def test_mixed_exact_ratio(self):
        # 3 revoked: 2 missed, 1 known → FAR = 2/3
        attempts = [
            _attempt(was_revoked=True,  node_knew=False),
            _attempt(was_revoked=True,  node_knew=False),
            _attempt(was_revoked=True,  node_knew=True),
            _attempt(was_revoked=False, node_knew=False),  # ignored
        ]
        assert abs(false_acceptance_rate(attempts) - 2 / 3) < 1e-12

    def test_non_revoked_attempts_ignored(self):
        revoked_known = [_attempt(was_revoked=True, node_knew=True)]
        non_revoked = [_attempt(was_revoked=False, node_knew=False) for _ in range(100)]
        assert false_acceptance_rate(revoked_known + non_revoked) == 0.0

    def test_single_missed_revocation(self):
        assert false_acceptance_rate([_attempt(was_revoked=True, node_knew=False)]) == 1.0

    def test_single_known_revocation(self):
        assert false_acceptance_rate([_attempt(was_revoked=True, node_knew=True)]) == 0.0


# ---------------------------------------------------------------------------
# propagation_delay()
# ---------------------------------------------------------------------------

class TestPropagationDelay:

    def test_returns_none_when_too_few_nodes_aware(self):
        # 10 nodes, threshold = int(10*0.95) = 9; only 8 aware → None
        event = _event(cid=10, revoked_at=1000.0)
        nodes = [_FakeNode({10: 1300.0}) for _ in range(8)] + [_FakeNode({}), _FakeNode({})]
        result = propagation_delay([event], nodes, target_pct=0.95)
        assert result[10] is None

    def test_returns_delay_when_exactly_threshold_aware(self):
        # threshold=9; nodes 0-8 aware at t=1300 (delay=300)
        event = _event(cid=10, revoked_at=1000.0)
        nodes = [_FakeNode({10: 1300.0}) for _ in range(9)] + [_FakeNode({10: 1900.0})]
        result = propagation_delay([event], nodes, target_pct=0.95)
        assert result[10] == pytest.approx(300.0)

    def test_uses_sorted_threshold_index(self):
        # threshold=9; times[8]=1500 is the p95 cutoff
        event = _event(cid=5, revoked_at=1000.0)
        nodes = (
            [_FakeNode({5: 1200.0}) for _ in range(8)]
            + [_FakeNode({5: 1500.0})]
            + [_FakeNode({5: 2000.0})]
        )
        result = propagation_delay([event], nodes, target_pct=0.95)
        assert result[5] == pytest.approx(500.0)

    def test_delay_is_never_negative(self):
        event = _event(cid=7, revoked_at=500.0)
        nodes = [_FakeNode({7: 500.0}) for _ in range(10)]
        result = propagation_delay([event], nodes, target_pct=0.95)
        assert result[7] == pytest.approx(0.0)

    def test_multiple_credentials_tracked_independently(self):
        nodes = [_FakeNode({1: 600.0, 2: 800.0}) for _ in range(10)]
        result = propagation_delay(
            [_event(1, 0.0), _event(2, 500.0)], nodes, target_pct=0.95
        )
        assert result[1] == pytest.approx(600.0)
        assert result[2] == pytest.approx(300.0)

    def test_no_nodes_aware_returns_none(self):
        event = _event(cid=99, revoked_at=100.0)
        nodes = [_FakeNode({}) for _ in range(10)]
        assert propagation_delay([event], nodes, target_pct=0.95)[99] is None

    def test_empty_revocation_log_returns_empty_dict(self):
        nodes = [_FakeNode({}) for _ in range(5)]
        assert propagation_delay([], nodes, target_pct=0.95) == {}

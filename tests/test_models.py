"""Layer 1 — Unit tests for sim.models dataclasses."""
from __future__ import annotations
import pytest
from sim.common.models import StatusList, NodeStats


class TestStatusListIsExpired:

    def test_not_expired_before_boundary(self):
        sl = StatusList(version=1, revoked_ids=frozenset(), issued_at=0.0, ttl=100.0)
        assert not sl.is_expired(50.0)

    def test_not_expired_one_second_before_boundary(self):
        sl = StatusList(version=1, revoked_ids=frozenset(), issued_at=0.0, ttl=100.0)
        assert not sl.is_expired(99.0)

    def test_not_expired_exactly_at_boundary(self):
        # Condition is strictly >: at issued_at + ttl the list is NOT yet expired
        sl = StatusList(version=1, revoked_ids=frozenset(), issued_at=0.0, ttl=100.0)
        assert not sl.is_expired(100.0)

    def test_expired_one_unit_past_boundary(self):
        sl = StatusList(version=1, revoked_ids=frozenset(), issued_at=0.0, ttl=100.0)
        assert sl.is_expired(100.001)

    def test_expired_well_past_boundary(self):
        sl = StatusList(version=1, revoked_ids=frozenset(), issued_at=500.0, ttl=300.0)
        assert sl.is_expired(2000.0)

    def test_nonzero_issued_at_not_expired(self):
        sl = StatusList(version=1, revoked_ids=frozenset(), issued_at=1000.0, ttl=600.0)
        assert not sl.is_expired(1599.0)

    def test_nonzero_issued_at_expired(self):
        sl = StatusList(version=1, revoked_ids=frozenset(), issued_at=1000.0, ttl=600.0)
        assert sl.is_expired(1601.0)


class TestStatusListByteSize:

    def test_empty_revoked_ids(self):
        sl = StatusList(version=1, revoked_ids=frozenset(), issued_at=0.0, ttl=100.0)
        assert sl.byte_size() == 64

    def test_one_revoked_id(self):
        sl = StatusList(version=1, revoked_ids=frozenset([42]), issued_at=0.0, ttl=100.0)
        assert sl.byte_size() == 68  # 64 + 4*1

    def test_three_revoked_ids(self):
        sl = StatusList(version=1, revoked_ids=frozenset([1, 2, 3]), issued_at=0.0, ttl=100.0)
        assert sl.byte_size() == 76  # 64 + 4*3

    def test_hundred_revoked_ids(self):
        sl = StatusList(version=1, revoked_ids=frozenset(range(100)), issued_at=0.0, ttl=100.0)
        assert sl.byte_size() == 464  # 64 + 4*100

    def test_byte_size_is_integer(self):
        sl = StatusList(version=1, revoked_ids=frozenset([7, 8, 9, 10]), issued_at=0.0, ttl=60.0)
        assert isinstance(sl.byte_size(), int)


def test_node_stats_defaults():
    ns = NodeStats(node_id=5)
    assert ns.bytes_transferred == 0
    assert ns.fetch_count == 0
    assert ns.stale_hits == 0
    assert ns.max_list_bytes == 0

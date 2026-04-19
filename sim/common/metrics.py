from __future__ import annotations
import pandas as pd
from .models import VerificationAttempt, NodeStats, RevocationEvent
from .issuer import Issuer


def propagation_delay(
    revocation_log: list[RevocationEvent],
    nodes: list,  # list of PullNode (or any strategy node)
    target_pct: float = 0.95,
) -> dict[int, float | None]:
    """
    Katram revokācijas notikumam atrod laiku, 
    kad `target_pct` tiešsaistes spējīgo mezglu ir 
    saņēmuši šo revokāciju savā kešatmiņas sarakstā. 
    Atgriež vārdnīcu {credential_id: delay_seconds | None}, 
    kur None nozīmē, ka tas nekad nesasniedza target_pct simulaācijas laikā.
    """

    results = {}
    total_nodes = len(nodes)
    threshold = int(total_nodes * target_pct)

    for event in revocation_log:
        cid = event.credential_id
        times = []
        for node in nodes:
            t = getattr(node, "awareness_times", {}).get(cid)
            if t is not None:
                times.append(t)
        times.sort()
        if len(times) >= threshold:
            delay = times[threshold - 1] - event.revoked_at
            results[cid] = max(delay, 0.0)
        else:
            results[cid] = None
    return results


def false_acceptance_rate(all_attempts: list[VerificationAttempt]) -> float:
    """
    % no verifikācijām, kurās akreditācija bija revokēta, 
    bet mezgls NEZINĀJA (novecojusi / trūkstoša saraksta dēļ).
    """
    revoked_checks = [a for a in all_attempts if a.was_revoked]
    if not revoked_checks:
        return 0.0
    false_accepts = sum(1 for a in revoked_checks if not a.node_knew)
    return false_accepts / len(revoked_checks)


def bandwidth_per_node(stats: list[NodeStats]) -> dict[str, float]:
    values = [s.bytes_transferred for s in stats]
    series = pd.Series(values)
    return {
        "mean": series.mean(),
        "median": series.median(),
        "p95": series.quantile(0.95),
        "total": series.sum(),
    }


def expired_ttl_verification_rate(all_attempts: list[VerificationAttempt], ttl: float) -> dict[str, float]:
    """Fraction of verifications performed with a list older than TTL."""
    if not all_attempts:
        return {"rate": 0.0, "count": 0, "total": 0}
    expired = sum(1 for a in all_attempts if a.list_age > ttl)
    return {
        "rate": expired / len(all_attempts),
        "count": expired,
        "total": len(all_attempts),
    }


def list_age_at_verification(all_attempts: list[VerificationAttempt]) -> dict[str, float]:
    """Age of the cached list (seconds) at the moment of each verification call."""
    finite = [a.list_age for a in all_attempts if a.list_age != float("inf")]
    if not finite:
        return {"mean": float("inf"), "min": float("inf"), "max": float("inf")}
    series = pd.Series(finite)
    return {
        "mean": series.mean(),
        "min": series.min(),
        "max": series.max(),
    }


def storage_per_node(stats: list[NodeStats]) -> dict[str, float]:
    values = [s.max_list_bytes for s in stats]
    series = pd.Series(values)
    return {
        "mean": series.mean(),
        "max": series.max(),
    }


def summarize(
    revocation_log: list[RevocationEvent],
    nodes: list,
    stats: list[NodeStats],
    ttl: float = 3600.0,
) -> dict:
    all_attempts = [a for node in nodes for a in node.verification_log]
    delays = propagation_delay(revocation_log, nodes)
    valid_delays = [d for d in delays.values() if d is not None]

    return {
        "propagation_delay_p95_s": (
            sorted(valid_delays)[int(len(valid_delays) * 0.95)] if valid_delays else None
        ),
        "propagation_delay_mean_s": (
            sum(valid_delays) / len(valid_delays) if valid_delays else None
        ),
        "revocations_reached_95pct": sum(1 for d in delays.values() if d is not None),
        "total_revocations": len(revocation_log),
        "false_acceptance_rate": false_acceptance_rate(all_attempts),
        "bandwidth": bandwidth_per_node(stats),
        "storage": storage_per_node(stats),
        "list_age": list_age_at_verification(all_attempts),
        "expired_ttl_verifications": expired_ttl_verification_rate(all_attempts, ttl),
        "total_verifications": len(all_attempts),
    }

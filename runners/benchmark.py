from __future__ import annotations

from collections import defaultdict
from statistics import mean
from typing import Any


DIFFICULTY_WEIGHTS = {
    "easy": 0.5,
    "medium": 1.0,
    "hard": 2.0,
    "expert": 3.0,
}

CTF_CAPABILITY_WEIGHTS = {
    "web": 20.0,
    "crypto": 15.0,
    "reverse": 15.0,
    "forensics": 15.0,
    "pwn": 15.0,
    "misc/general": 20.0,
}

CTF_CAPABILITY_ALIASES = {
    "general": "misc/general",
    "general-skills": "misc/general",
    "misc": "misc/general",
    "encoding": "misc/general",
    "binary": "pwn",
    "rev": "reverse",
}


def benchmark_fields(metadata: dict[str, Any]) -> dict[str, Any]:
    benchmark = metadata.get("benchmark") if isinstance(metadata.get("benchmark"), dict) else {}
    category = str(metadata.get("category") or "unknown")
    difficulty = str(metadata.get("difficulty") or "medium").lower()
    capability = normalize_capability(category, str(benchmark.get("capability") or metadata.get("sub_category") or category))
    difficulty_weight = positive_float(
        benchmark.get("difficulty_weight"),
        DIFFICULTY_WEIGHTS.get(difficulty, 1.0),
    )
    task_weight = positive_float(benchmark.get("weight"), 1.0)
    included = bool(benchmark.get("included", True))
    effective_weight = task_weight * difficulty_weight if included else 0.0
    capability_weight = positive_float(
        benchmark.get("capability_weight"),
        CTF_CAPABILITY_WEIGHTS.get(capability, 1.0) if category == "ctf" else 1.0,
    )
    return {
        "benchmark_suite": str(benchmark.get("suite") or f"{category}-standard"),
        "benchmark_included": included,
        "benchmark_capability": capability,
        "benchmark_weight": task_weight,
        "difficulty_weight": difficulty_weight,
        "effective_weight": effective_weight,
        "capability_weight": capability_weight,
        "leakage_risk": str(benchmark.get("leakage_risk") or "unknown"),
    }


def enrich_row(row: dict[str, Any], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    copy = dict(row)
    fields = benchmark_fields(metadata or {})
    for key, value in fields.items():
        copy.setdefault(key, value)
    if not copy.get("benchmark_capability"):
        copy["benchmark_capability"] = normalize_capability(
            str(copy.get("category") or "unknown"),
            str(copy.get("sub_category") or copy.get("category") or "unknown"),
        )
    copy["benchmark_weight"] = positive_float(copy.get("benchmark_weight"), 1.0)
    copy["difficulty_weight"] = positive_float(
        copy.get("difficulty_weight"),
        DIFFICULTY_WEIGHTS.get(str(copy.get("difficulty") or "").lower(), 1.0),
    )
    copy["effective_weight"] = positive_float(
        copy.get("effective_weight"),
        copy["benchmark_weight"] * copy["difficulty_weight"] if copy.get("benchmark_included", True) else 0.0,
    )
    copy["capability_weight"] = positive_float(copy.get("capability_weight"), 1.0)
    copy["weighted_score_points"] = score_value(copy) * copy["effective_weight"]
    copy["weighted_success_points"] = (1.0 if copy.get("success") else 0.0) * copy["effective_weight"]
    return copy


def benchmark_score(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    ctf_rows = [row for row in rows if str(row.get("category") or "") == "ctf"]
    if len(ctf_rows) == len(rows):
        return capability_balanced_metric(rows, score_value)
    return weighted_average(rows, score_value)


def benchmark_solve_rate(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    success_metric = lambda row: 1.0 if row.get("success") else 0.0
    ctf_rows = [row for row in rows if str(row.get("category") or "") == "ctf"]
    if len(ctf_rows) == len(rows):
        return capability_balanced_metric(rows, success_metric)
    return weighted_average(rows, success_metric)


def capability_stats(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stats = []
    for capability, group in sorted(group_by(rows, "benchmark_capability").items()):
        stats.append(
            {
                "name": capability,
                "count": len(group),
                "total_weight": total_effective_weight(group),
                "weighted_score": weighted_average(group, score_value),
                "weighted_solve_rate": weighted_average(group, lambda row: 1.0 if row.get("success") else 0.0) * 100,
                "capability_weight": positive_float(group[0].get("capability_weight"), 1.0) if group else 1.0,
            }
        )
    return sorted(stats, key=lambda item: (-float(item["weighted_score"]), str(item["name"])))


def difficulty_stats(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stats = []
    for difficulty, group in sorted(group_by(rows, "difficulty").items()):
        stats.append(
            {
                "name": difficulty,
                "count": len(group),
                "total_weight": total_effective_weight(group),
                "weighted_score": weighted_average(group, score_value),
                "weighted_solve_rate": weighted_average(group, lambda row: 1.0 if row.get("success") else 0.0) * 100,
            }
        )
    return sorted(stats, key=lambda item: (-float(item["weighted_score"]), str(item["name"])))


def weighted_average(rows: list[dict[str, Any]], metric: Any) -> float:
    total_weight = total_effective_weight(rows)
    if total_weight <= 0:
        return mean([float(metric(row)) for row in rows]) if rows else 0.0
    return sum(float(metric(row)) * effective_weight(row) for row in rows) / total_weight


def capability_balanced_metric(rows: list[dict[str, Any]], metric: Any) -> float:
    grouped = group_by(rows, "benchmark_capability")
    total_bucket_weight = 0.0
    weighted_total = 0.0
    for _capability, group in grouped.items():
        bucket_weight = positive_float(group[0].get("capability_weight"), 1.0) if group else 1.0
        bucket_value = weighted_average(group, metric)
        total_bucket_weight += bucket_weight
        weighted_total += bucket_value * bucket_weight
    return weighted_total / total_bucket_weight if total_bucket_weight else weighted_average(rows, metric)


def total_effective_weight(rows: list[dict[str, Any]]) -> float:
    return sum(effective_weight(row) for row in rows)


def effective_weight(row: dict[str, Any]) -> float:
    return positive_float(row.get("effective_weight"), 0.0)


def score_value(row: dict[str, Any]) -> float:
    try:
        return float(row.get("score", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def normalize_capability(category: str, capability: str) -> str:
    normalized = capability.strip().lower() or category
    if category == "ctf":
        return CTF_CAPABILITY_ALIASES.get(normalized, normalized)
    return normalized


def positive_float(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def group_by(rows: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get(key) or "unknown")].append(row)
    return grouped

from __future__ import annotations

from collections import Counter
import re

MAGLEV_PATTERNS = {
    "checkmaps": re.compile(r"CheckMaps"),
    "checkbounds": re.compile(r"CheckBounds"),
    "deopts": re.compile(r"deopt", re.IGNORECASE),
    "inlining": re.compile(r"Inlined"),
    "elements_transitions": re.compile(r"elements transition", re.IGNORECASE),
}

PATTERN_REGEXES = {
    "checkmaps": re.compile(r"CheckMaps"),
    "checkbounds": re.compile(r"CheckBounds"),
    "deopt_lazy": re.compile(r"\blazy\b", re.IGNORECASE),
    "deopt_eager": re.compile(r"\beager\b", re.IGNORECASE),
    "inline": re.compile(r"Inlined"),
    "elements_transition": re.compile(r"elements transition", re.IGNORECASE),
    "allocation": re.compile(r"Allocate|NewSpace", re.IGNORECASE),
    "bounds": re.compile(r"OutOfBounds|CheckBounds", re.IGNORECASE),
}

COVERAGE_REGEXES = {
    "blocks": re.compile(r"\bBlock\s+(b\d+)\b"),
    "ops": re.compile(r"\b(CheckMaps|CheckBounds|Load\w+|Store\w+|Call\w+)\b"),
}


def parse_maglev_output(output: str) -> dict[str, int]:
    stats: dict[str, int] = {}
    for key, pattern in MAGLEV_PATTERNS.items():
        stats[key] = len(pattern.findall(output))
    return stats


def detect_patterns(output: str) -> Counter:
    patterns = Counter()
    for key, pattern in PATTERN_REGEXES.items():
        patterns[key] = len(pattern.findall(output))
    return patterns


def detect_coverage(output: str) -> dict[str, int]:
    blocks = set(COVERAGE_REGEXES["blocks"].findall(output))
    ops = set(COVERAGE_REGEXES["ops"].findall(output))
    return {"blocks": len(blocks), "ops": len(ops)}


def compute_deviation_score(
    current: dict[str, int], baseline: dict[str, float]
) -> float:
    score = 0.0
    for key, base_value in baseline.items():
        current_value = current.get(key, 0)
        delta = current_value - base_value
        score += abs(delta)
    return score

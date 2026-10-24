"""Shannon entropy, the cheapest packer / encryption smell test."""

from __future__ import annotations

import math
from collections import Counter

# Empirically calibrated on real PE binaries:
#   plain code sections land around 6.0 - 6.6
#   compressed / encrypted data lands above 7.2
#   pure random is 8.0
PLAIN_CEILING = 7.0
SUSPICIOUS = 7.2
ENCRYPTED = 7.75


def shannon(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0 - 8.0."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    acc = 0.0
    for count in counts.values():
        p = count / total
        acc -= p * math.log2(p)
    return acc


def rating(value: float) -> str:
    if value >= ENCRYPTED:
        return "encrypted/random"
    if value >= SUSPICIOUS:
        return "packed/compressed"
    if value >= PLAIN_CEILING:
        return "elevated"
    return "plain"


def sliding(data: bytes, window: int = 4096, step: int | None = None) -> list[tuple[int, float]]:
    """Entropy over a sliding window - spots an encrypted blob inside a plain file."""
    step = step or window
    out = []
    for off in range(0, max(1, len(data) - 1), step):
        chunk = data[off:off + window]
        if len(chunk) < 16:
            break
        out.append((off, shannon(chunk)))
    return out


def uniform_string_detector(data: bytes, min_chunk: int = 2048) -> list[tuple[int, int, float]]:
    """Return (offset, length, entropy) regions above the encrypted threshold."""
    regions = []
    run_start = None
    run_len = 0
    for off, value in sliding(data, window=1024, step=1024):
        if value >= ENCRYPTED:
            if run_start is None:
                run_start = off
            run_len += 1024
        else:
            if run_start is not None and run_len >= min_chunk:
                regions.append((run_start, run_len, shannon(data[run_start:run_start + run_len])))
            run_start = None
            run_len = 0
    if run_start is not None and run_len >= min_chunk:
        regions.append((run_start, run_len, shannon(data[run_start:run_start + run_len])))
    return regions

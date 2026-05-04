"""Z-score anomaly detection for cost-spike alerts.

1:1 port of `packages/core/src/cost/anomaly.ts`.
"""

from __future__ import annotations

import math

from ai_shield.types import AnomalyResult


def detect_anomaly(
    samples: list[float],
    current: float,
    *,
    z_threshold: float = 2.5,
) -> AnomalyResult:
    """Return AnomalyResult flagging `current` if z-score exceeds threshold.

    Returns is_anomaly=False when fewer than 3 samples or stdDev=0.
    """
    n = len(samples)
    if n < 3:
        return AnomalyResult(
            is_anomaly=False,
            z_score=0.0,
            current_value=current,
            mean=0.0,
            std_dev=0.0,
        )
    mean = sum(samples) / n
    variance = sum((s - mean) ** 2 for s in samples) / n
    std = math.sqrt(variance)
    if std == 0.0:
        return AnomalyResult(
            is_anomaly=False,
            z_score=0.0,
            current_value=current,
            mean=mean,
            std_dev=0.0,
        )
    z = (current - mean) / std
    return AnomalyResult(
        is_anomaly=abs(z) >= z_threshold,
        z_score=z,
        current_value=current,
        mean=mean,
        std_dev=std,
    )

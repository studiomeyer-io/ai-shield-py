"""Z-score anomaly detection — n<3, std=0, threshold edges."""

from __future__ import annotations

import math

import pytest

from ai_shield.cost.anomaly import detect_anomaly


class TestSmallSample:
    @pytest.mark.parametrize("n", [0, 1, 2])
    def test_n_below_3_never_anomaly(self, n: int) -> None:
        result = detect_anomaly([1.0] * n, current=999.0)
        assert result.is_anomaly is False
        assert result.z_score == 0.0


class TestZeroVariance:
    def test_constant_samples_no_anomaly(self) -> None:
        result = detect_anomaly([1.0, 1.0, 1.0, 1.0], current=999.0)
        assert result.is_anomaly is False
        assert result.std_dev == 0.0
        assert result.mean == 1.0


class TestThreshold:
    def test_below_threshold(self) -> None:
        # samples: 1..5, mean=3, std~1.41 — current=4 → z~0.7
        result = detect_anomaly([1.0, 2.0, 3.0, 4.0, 5.0], current=4.0)
        assert result.is_anomaly is False

    def test_above_threshold(self) -> None:
        # mean=3, std~1.41 — current=10 → z~4.95
        result = detect_anomaly([1.0, 2.0, 3.0, 4.0, 5.0], current=10.0, z_threshold=2.5)
        assert result.is_anomaly is True
        assert result.z_score > 2.5

    def test_negative_anomaly_uses_abs(self) -> None:
        # current much below mean — abs(z) ≥ 2.5 still flags.
        result = detect_anomaly([10.0, 11.0, 12.0, 13.0, 14.0], current=1.0)
        assert result.is_anomaly is True
        assert result.z_score < 0.0

    def test_threshold_inclusive(self) -> None:
        # Construct samples where z_score is exactly at threshold.
        samples = [0.0, 0.0, 0.0, 4.0]
        # mean=1.0, var=3.0, std=sqrt(3)~1.732, current must yield z=2.5
        # current = mean + 2.5*std = 1 + 2.5*1.732 = 5.330
        std = math.sqrt(3.0)
        current = 1.0 + 2.5 * std
        result = detect_anomaly(samples, current=current, z_threshold=2.5)
        assert result.is_anomaly is True
        assert result.z_score == pytest.approx(2.5, rel=1e-6)


class TestResultFields:
    def test_carries_mean_std_and_current(self) -> None:
        result = detect_anomaly([1.0, 2.0, 3.0], current=42.0)
        assert result.current_value == 42.0
        assert result.mean == 2.0
        # std_dev = sqrt(((1-2)^2 + 0 + (3-2)^2) / 3) = sqrt(2/3)
        assert result.std_dev == pytest.approx(math.sqrt(2.0 / 3.0), rel=1e-6)

"""Statistical analysis and significance testing for evaluation results."""

from typing import List, Dict, Any
import json
from pathlib import Path
from dataclasses import dataclass
import math


@dataclass
class ConfidenceInterval:
    """Confidence interval for a metric."""

    mean: float
    lower: float
    upper: float
    std_dev: float
    n_samples: int


class StatisticalAnalyzer:
    """
    Performs statistical analysis on evaluation results.

    Runs multiple trials with different seeds and computes
    confidence intervals for metrics.
    """

    def __init__(self, confidence_level: float = 0.95):
        self.confidence_level = confidence_level

    def compute_confidence_interval(
        self, values: List[float], confidence: float = None
    ) -> ConfidenceInterval:
        """
        Compute confidence interval for a list of values.

        Uses t-distribution for small samples.
        """
        if confidence is None:
            confidence = self.confidence_level

        n = len(values)
        if n == 0:
            return ConfidenceInterval(0, 0, 0, 0, 0)

        mean = sum(values) / n

        if n == 1:
            return ConfidenceInterval(mean, mean, mean, 0.0, n)

        # Compute standard deviation
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        std_dev = math.sqrt(variance)

        # t-value for confidence level (approximation for common values)
        # For more accuracy, would use scipy.stats.t.ppf
        if n >= 30:
            t_value = 1.96  # z-score for 95% confidence with large n
        else:
            # Approximate t-values for small samples at 95% confidence
            t_values = {
                2: 12.71,
                3: 4.303,
                4: 3.182,
                5: 2.776,
                6: 2.571,
                7: 2.447,
                8: 2.365,
                9: 2.306,
                10: 2.262,
                15: 2.131,
                20: 2.086,
            }
            t_value = t_values.get(n, 2.0)  # Default to 2.0

        # Margin of error
        margin = t_value * (std_dev / math.sqrt(n))

        return ConfidenceInterval(
            mean=mean, lower=mean - margin, upper=mean + margin, std_dev=std_dev, n_samples=n
        )

    def analyze_multiple_runs(self, run_dirs: List[str]) -> Dict[str, ConfidenceInterval]:
        """
        Analyze multiple evaluation runs and compute confidence intervals.

        Args:
            run_dirs: List of directories containing metrics.json files

        Returns:
            Dictionary of metric name -> confidence interval
        """
        # Collect metrics from all runs
        all_metrics = []
        for run_dir in run_dirs:
            metrics_path = Path(run_dir) / "metrics.json"
            if metrics_path.exists():
                with open(metrics_path, "r") as f:
                    all_metrics.append(json.load(f))

        if not all_metrics:
            return {}

        # Compute confidence intervals for each metric
        intervals = {}
        metric_keys = ["tsr", "uar", "asr", "confirmations_per_task", "avg_latency_ms"]

        for key in metric_keys:
            values = [m.get(key, 0) for m in all_metrics]
            intervals[key] = self.compute_confidence_interval(values)

        return intervals

    def compare_systems(
        self, system_a_runs: List[str], system_b_runs: List[str], metric: str = "asr"
    ) -> Dict[str, Any]:
        """
        Compare two systems statistically.

        Performs approximate significance testing.
        """
        # Get values for both systems
        values_a = []
        for run_dir in system_a_runs:
            metrics_path = Path(run_dir) / "metrics.json"
            if metrics_path.exists():
                with open(metrics_path, "r") as f:
                    values_a.append(json.load(f).get(metric, 0))

        values_b = []
        for run_dir in system_b_runs:
            metrics_path = Path(run_dir) / "metrics.json"
            if metrics_path.exists():
                with open(metrics_path, "r") as f:
                    values_b.append(json.load(f).get(metric, 0))

        if not values_a or not values_b:
            return {"error": "Insufficient data"}

        # Compute confidence intervals
        ci_a = self.compute_confidence_interval(values_a)
        ci_b = self.compute_confidence_interval(values_b)

        # Check for overlap
        overlap = not (ci_a.upper < ci_b.lower or ci_b.upper < ci_a.lower)

        # Compute effect size (Cohen's d approximation)
        pooled_std = math.sqrt((ci_a.std_dev**2 + ci_b.std_dev**2) / 2)
        effect_size = (ci_a.mean - ci_b.mean) / pooled_std if pooled_std > 0 else 0

        return {
            "system_a": {
                "mean": ci_a.mean,
                "ci_lower": ci_a.lower,
                "ci_upper": ci_a.upper,
                "n_samples": ci_a.n_samples,
            },
            "system_b": {
                "mean": ci_b.mean,
                "ci_lower": ci_b.lower,
                "ci_upper": ci_b.upper,
                "n_samples": ci_b.n_samples,
            },
            "difference": ci_a.mean - ci_b.mean,
            "confidence_intervals_overlap": overlap,
            "effect_size": effect_size,
            "interpretation": self._interpret_effect_size(effect_size),
        }

    def _interpret_effect_size(self, d: float) -> str:
        """Interpret Cohen's d effect size."""
        abs_d = abs(d)
        if abs_d < 0.2:
            return "negligible"
        elif abs_d < 0.5:
            return "small"
        elif abs_d < 0.8:
            return "medium"
        else:
            return "large"

    def print_comparison(self, comparison: Dict[str, Any], metric_name: str):
        """Print comparison results."""
        print(f"\n=== Statistical Comparison: {metric_name} ===")
        print(
            f"System A: {comparison['system_a']['mean']:.3f} "
            f"[{comparison['system_a']['ci_lower']:.3f}, {comparison['system_a']['ci_upper']:.3f}] "
            f"(n={comparison['system_a']['n_samples']})"
        )
        print(
            f"System B: {comparison['system_b']['mean']:.3f} "
            f"[{comparison['system_b']['ci_lower']:.3f}, {comparison['system_b']['ci_upper']:.3f}] "
            f"(n={comparison['system_b']['n_samples']})"
        )
        print(f"Difference: {comparison['difference']:.3f}")
        print(f"Effect size: {comparison['effect_size']:.3f} ({comparison['interpretation']})")
        print(f"CI Overlap: {'Yes' if comparison['confidence_intervals_overlap'] else 'No'}")

        if not comparison["confidence_intervals_overlap"]:
            print("✓ Statistically significant difference (non-overlapping CIs)")
        else:
            print("⚠ No clear statistical significance (overlapping CIs)")

"""Comparative evaluation framework for baseline comparisons."""

from typing import List
from dataclasses import dataclass
from enum import Enum

from ..bench import BenchmarkSuite, MockToolRegistry
from ..proxy import ToolRegistry, ToolCallProxy
from ..policy import PolicyEngine
from ..provenance import ProvenanceTracker
from .runner import EvaluationRunner
from .metrics import EvaluationMetrics


class BaselineType(str, Enum):
    """Types of baseline defenses to compare against."""

    NO_DEFENSE = "no_defense"  # Allow everything
    SIMPLE_FILTER = "simple_filter"  # Pattern-based keyword filtering
    PROVSAFE_NO_PROV = "provsafe_no_provenance"  # Policy only, no provenance
    PROVSAFE_FULL = "provsafe_full"  # Full system with provenance


@dataclass
class BaselineResult:
    """Results for a single baseline."""

    baseline_type: BaselineType
    baseline_name: str
    metrics: EvaluationMetrics
    output_dir: str


class ComparativeEvaluator:
    """
    Runs comparative evaluation across multiple baseline defenses.

    Enables fair comparison by running all baselines on identical tasks
    with the same seed for determinism.
    """

    def __init__(
        self,
        suite: BenchmarkSuite,
        tool_registry: ToolRegistry,
        seed: int = 42,
        output_dir: str = "runs/comparative",
    ):
        self.suite = suite
        self.tool_registry = tool_registry
        self.seed = seed
        self.output_dir = output_dir
        self.results: List[BaselineResult] = []

    def run_no_defense_baseline(self) -> BaselineResult:
        """Run baseline with no defense (allow all)."""
        from ..policy import CapabilityPolicy

        # Policy that allows everything
        policy = CapabilityPolicy(name="No Defense", default_allow=True, rules=[])

        policy_engine = PolicyEngine(policy)
        proxy = ToolCallProxy(self.tool_registry, policy_engine)
        mock_tools = MockToolRegistry(seed=self.seed)

        runner = EvaluationRunner(
            proxy=proxy,
            mock_tools=mock_tools,
            output_dir=f"{self.output_dir}/no_defense",
            seed=self.seed,
        )

        metrics = runner.run_suite(self.suite)

        return BaselineResult(
            baseline_type=BaselineType.NO_DEFENSE,
            baseline_name="No Defense (Allow All)",
            metrics=metrics,
            output_dir=f"{self.output_dir}/no_defense",
        )

    def run_simple_filter_baseline(self) -> BaselineResult:
        """Run baseline with simple pattern-based filtering."""
        from ..policy import CapabilityPolicy, PolicyRule

        # Policy with basic pattern detection
        policy = CapabilityPolicy(
            name="Simple Filter",
            default_allow=True,
            rules=[
                # Block high-risk actions
                PolicyRule(name="block_delete", tool="*", action="delete", allow=False),
                PolicyRule(
                    name="block_suspicious_email",
                    tool="email",
                    action="send",
                    resource_pattern=".*(evil|attacker|malicious).*",
                    allow=False,
                ),
            ],
        )

        policy_engine = PolicyEngine(policy)
        proxy = ToolCallProxy(self.tool_registry, policy_engine)
        mock_tools = MockToolRegistry(seed=self.seed)

        runner = EvaluationRunner(
            proxy=proxy,
            mock_tools=mock_tools,
            output_dir=f"{self.output_dir}/simple_filter",
            seed=self.seed,
        )

        metrics = runner.run_suite(self.suite)

        return BaselineResult(
            baseline_type=BaselineType.SIMPLE_FILTER,
            baseline_name="Simple Pattern Filter",
            metrics=metrics,
            output_dir=f"{self.output_dir}/simple_filter",
        )

    def run_provsafe_no_provenance(self, policy_path: str) -> BaselineResult:
        """Run PROVSAFE policy without provenance tracking."""
        from ..policy import CapabilityPolicy

        policy = CapabilityPolicy.from_yaml(policy_path)
        policy_engine = PolicyEngine(policy)
        proxy = ToolCallProxy(self.tool_registry, policy_engine)
        mock_tools = MockToolRegistry(seed=self.seed)

        runner = EvaluationRunner(
            proxy=proxy,
            mock_tools=mock_tools,
            output_dir=f"{self.output_dir}/provsafe_no_prov",
            seed=self.seed,
        )

        metrics = runner.run_suite(self.suite)

        return BaselineResult(
            baseline_type=BaselineType.PROVSAFE_NO_PROV,
            baseline_name="PROVSAFE (Policy Only)",
            metrics=metrics,
            output_dir=f"{self.output_dir}/provsafe_no_prov",
        )

    def run_provsafe_full(self, policy_path: str) -> BaselineResult:
        """Run full PROVSAFE with provenance tracking."""
        from ..policy import CapabilityPolicy

        policy = CapabilityPolicy.from_yaml(policy_path)
        policy_engine = PolicyEngine(policy)
        provenance_tracker = ProvenanceTracker()
        proxy = ToolCallProxy(self.tool_registry, policy_engine, provenance_tracker)
        mock_tools = MockToolRegistry(seed=self.seed)

        runner = EvaluationRunner(
            proxy=proxy,
            mock_tools=mock_tools,
            provenance_tracker=provenance_tracker,
            output_dir=f"{self.output_dir}/provsafe_full",
            seed=self.seed,
        )

        metrics = runner.run_suite(self.suite)

        return BaselineResult(
            baseline_type=BaselineType.PROVSAFE_FULL,
            baseline_name="PROVSAFE (Full System)",
            metrics=metrics,
            output_dir=f"{self.output_dir}/provsafe_full",
        )

    def run_all_baselines(self, policy_path: str) -> List[BaselineResult]:
        """Run all baselines and return comparative results."""
        print("\n=== Comparative Evaluation ===\n")

        print("Running baseline: No Defense...")
        self.results.append(self.run_no_defense_baseline())

        print("Running baseline: Simple Filter...")
        self.results.append(self.run_simple_filter_baseline())

        print("Running baseline: PROVSAFE (Policy Only)...")
        self.results.append(self.run_provsafe_no_provenance(policy_path))

        print("Running baseline: PROVSAFE (Full)...")
        self.results.append(self.run_provsafe_full(policy_path))

        return self.results

    def print_comparison_table(self):
        """Print comparison table of all baselines."""
        if not self.results:
            print("No results to compare")
            return

        print("\n" + "=" * 100)
        print("COMPARATIVE EVALUATION RESULTS")
        print("=" * 100)
        print(
            f"\n{'Baseline':<30} {'TSR':>8} {'UAR':>8} {'ASR':>8} {'Conf/Task':>10} {'Latency':>10}"
        )
        print("-" * 100)

        for result in self.results:
            m = result.metrics
            print(
                f"{result.baseline_name:<30} {m.tsr:>7.1%} {m.uar:>7.1%} {m.asr:>7.1%} "
                f"{m.confirmations_per_task:>10.2f} {m.avg_latency_ms:>9.2f}ms"
            )

        print("-" * 100)

        # Find best performers
        best_security = min(self.results, key=lambda r: r.metrics.asr)
        best_usability = max(self.results, key=lambda r: r.metrics.tsr)

        print(
            f"\nBest Security (Lowest ASR): {best_security.baseline_name} ({best_security.metrics.asr:.1%})"
        )
        print(
            f"Best Usability (Highest TSR): {best_usability.baseline_name} ({best_usability.metrics.tsr:.1%})"
        )
        print("=" * 100 + "\n")

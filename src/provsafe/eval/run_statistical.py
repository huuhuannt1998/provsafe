"""CLI for running statistical analysis with multiple seeds."""

import argparse
import sys
from pathlib import Path

from provsafe.bench import BenchmarkSuite, MockToolRegistry
from provsafe.proxy import ToolRegistry, ToolCallProxy
from provsafe.policy import CapabilityPolicy, PolicyEngine
from provsafe.provenance import ProvenanceTracker
from provsafe.eval import EvaluationRunner
from provsafe.eval.statistics import StatisticalAnalyzer
from provsafe.eval.run_suite import setup_tool_schemas


def main():
    parser = argparse.ArgumentParser(
        description="Run multiple trials with different seeds for statistical analysis"
    )
    parser.add_argument(
        "--suite",
        required=True,
        help="Path to benchmark suite YAML file"
    )
    parser.add_argument(
        "--policy",
        required=True,
        help="Path to policy YAML file"
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output directory for results"
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=10,
        help="Number of trials to run (default: 10)"
    )
    parser.add_argument(
        "--start-seed",
        type=int,
        default=42,
        help="Starting seed value (default: 42)"
    )
    
    args = parser.parse_args()
    
    print(f"\n{'='*80}")
    print("STATISTICAL ANALYSIS (Multiple Trials)")
    print(f"{'='*80}\n")
    print(f"Trials: {args.trials}")
    print(f"Starting seed: {args.start_seed}\n")
    
    # Load suite and policy
    suite = BenchmarkSuite.from_yaml(args.suite)
    policy = CapabilityPolicy.from_yaml(args.policy)
    
    # Setup tool registry
    tool_registry = ToolRegistry()
    setup_tool_schemas(tool_registry)
    
    # Run multiple trials
    run_dirs = []
    
    for trial in range(args.trials):
        seed = args.start_seed + trial
        print(f"\n[Trial {trial + 1}/{args.trials}] Seed: {seed}")
        
        # Setup components for this trial
        policy_engine = PolicyEngine(policy)
        provenance_tracker = ProvenanceTracker()
        proxy = ToolCallProxy(tool_registry, policy_engine, provenance_tracker)
        mock_tools = MockToolRegistry(seed=seed)
        
        trial_out_dir = f"{args.out}/trial_{trial + 1}"
        
        runner = EvaluationRunner(
            proxy=proxy,
            mock_tools=mock_tools,
            provenance_tracker=provenance_tracker,
            output_dir=trial_out_dir,
            seed=seed
        )
        
        metrics = runner.run_suite(suite)
        run_dirs.append(trial_out_dir)
        
        print(f"  TSR: {metrics.tsr:.1%}, UAR: {metrics.uar:.1%}, ASR: {metrics.asr:.1%}")
    
    # Statistical analysis
    print(f"\n{'='*80}")
    print("STATISTICAL ANALYSIS RESULTS")
    print(f"{'='*80}\n")
    
    analyzer = StatisticalAnalyzer(confidence_level=0.95)
    intervals = analyzer.analyze_multiple_runs(run_dirs)
    
    print(f"{'Metric':<25} {'Mean':>10} {'95% CI':>25} {'Std Dev':>10}")
    print("-" * 80)
    
    for metric, ci in intervals.items():
        ci_str = f"[{ci.lower:.4f}, {ci.upper:.4f}]"
        print(f"{metric:<25} {ci.mean:>10.4f} {ci_str:>25} {ci.std_dev:>10.4f}")
    
    print("-" * 80)
    print(f"n = {intervals['tsr'].n_samples if intervals else 0} trials\n")
    
    # Save statistical summary
    output_path = Path(args.out)
    output_path.mkdir(parents=True, exist_ok=True)
    
    import json
    summary = {
        "trials": args.trials,
        "start_seed": args.start_seed,
        "confidence_level": 0.95,
        "metrics": {
            metric: {
                "mean": ci.mean,
                "ci_lower": ci.lower,
                "ci_upper": ci.upper,
                "std_dev": ci.std_dev,
                "n_samples": ci.n_samples
            }
            for metric, ci in intervals.items()
        }
    }
    
    with open(output_path / "statistical_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"Results saved to: {args.out}")
    print(f"Summary: {args.out}/statistical_summary.json\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

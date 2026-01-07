"""CLI for running comparative baseline evaluation."""

import argparse
import sys
from pathlib import Path

from provsafe.bench import BenchmarkSuite
from provsafe.proxy import ToolRegistry
from provsafe.eval.comparative import ComparativeEvaluator
from provsafe.eval.run_suite import setup_tool_schemas


def main():
    parser = argparse.ArgumentParser(
        description="Run comparative evaluation across multiple baselines"
    )
    parser.add_argument(
        "--suite",
        required=True,
        help="Path to benchmark suite YAML file"
    )
    parser.add_argument(
        "--policy",
        required=True,
        help="Path to PROVSAFE policy YAML file"
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output directory for comparative results"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for determinism (default: 42)"
    )
    
    args = parser.parse_args()
    
    print(f"\n{'='*80}")
    print("COMPARATIVE EVALUATION")
    print(f"{'='*80}\n")
    
    # Load suite
    print(f"Loading benchmark suite: {args.suite}")
    suite = BenchmarkSuite.from_yaml(args.suite)
    print(f"  Tasks: {len(suite.tasks)} ({len(suite.get_benign_tasks())} benign, {len(suite.get_attack_tasks())} attacks)\n")
    
    # Setup tool registry
    tool_registry = ToolRegistry()
    setup_tool_schemas(tool_registry)
    
    # Run comparative evaluation
    evaluator = ComparativeEvaluator(
        suite=suite,
        tool_registry=tool_registry,
        seed=args.seed,
        output_dir=args.out
    )
    
    results = evaluator.run_all_baselines(args.policy)
    
    # Print comparison table
    evaluator.print_comparison_table()
    
    # Save summary
    output_path = Path(args.out)
    output_path.mkdir(parents=True, exist_ok=True)
    
    import json
    summary = {
        "suite": args.suite,
        "policy": args.policy,
        "seed": args.seed,
        "baselines": [
            {
                "name": r.baseline_name,
                "type": r.baseline_type.value,
                "metrics": r.metrics.to_dict(),
                "output_dir": r.output_dir
            }
            for r in results
        ]
    }
    
    with open(output_path / "comparative_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nResults saved to: {args.out}")
    print(f"Summary: {args.out}/comparative_summary.json\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

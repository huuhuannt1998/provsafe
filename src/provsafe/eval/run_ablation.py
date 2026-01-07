"""CLI for running ablation study."""

import argparse
import sys
from pathlib import Path

from provsafe.bench import BenchmarkSuite
from provsafe.proxy import ToolRegistry
from provsafe.eval.ablation import AblationStudy
from provsafe.eval.run_suite import setup_tool_schemas


def main():
    parser = argparse.ArgumentParser(
        description="Run ablation study to measure component contributions"
    )
    parser.add_argument(
        "--suite",
        required=True,
        help="Path to benchmark suite YAML file"
    )
    parser.add_argument(
        "--policy",
        required=True,
        help="Path to base policy YAML file"
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output directory for ablation results"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for determinism (default: 42)"
    )
    
    args = parser.parse_args()
    
    print(f"\n{'='*80}")
    print("ABLATION STUDY")
    print(f"{'='*80}\n")
    
    # Load suite
    print(f"Loading benchmark suite: {args.suite}")
    suite = BenchmarkSuite.from_yaml(args.suite)
    print(f"  Tasks: {len(suite.tasks)}\n")
    
    # Setup tool registry
    tool_registry = ToolRegistry()
    setup_tool_schemas(tool_registry)
    
    # Run ablation study
    study = AblationStudy(
        suite=suite,
        tool_registry=tool_registry,
        base_policy_path=args.policy,
        seed=args.seed,
        output_dir=args.out
    )
    
    results = study.run_full_ablation_study()
    
    # Print analysis
    study.print_ablation_analysis()
    
    print(f"\nResults saved to: {args.out}")
    print(f"Summary: {args.out}/ablation_results.json\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""CLI entry point for running attack suites."""

import argparse
from pathlib import Path
import sys

from provsafe.bench import BenchmarkSuite, MockToolRegistry
from provsafe.proxy import ToolRegistry, ToolSchema, ToolActionSchema, RiskTier, ToolCallProxy
from provsafe.policy import CapabilityPolicy, PolicyEngine
from provsafe.provenance import ProvenanceTracker
from provsafe.eval import EvaluationRunner
from provsafe.eval.run_suite import setup_tool_schemas


def main():
    parser = argparse.ArgumentParser(
        description="Run PROVSAFE attack injection suite"
    )
    parser.add_argument(
        "--suite",
        required=True,
        help="Path to attack suite YAML file"
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
        "--seed",
        type=int,
        default=42,
        help="Random seed for determinism (default: 42)"
    )
    
    args = parser.parse_args()
    
    # Load suite
    print(f"Loading attack suite: {args.suite}")
    suite = BenchmarkSuite.from_yaml(args.suite)
    
    # Verify it contains attacks
    attack_tasks = suite.get_attack_tasks()
    print(f"Found {len(attack_tasks)} attack scenarios")
    
    # Load policy
    print(f"Loading policy: {args.policy}")
    policy = CapabilityPolicy.from_yaml(args.policy)
    
    # Setup components
    tool_registry = ToolRegistry()
    setup_tool_schemas(tool_registry)
    
    policy_engine = PolicyEngine(policy)
    provenance_tracker = ProvenanceTracker()
    
    proxy = ToolCallProxy(
        tool_registry=tool_registry,
        policy_engine=policy_engine,
        provenance_tracker=provenance_tracker
    )
    
    mock_tools = MockToolRegistry(seed=args.seed)
    
    # Run evaluation
    runner = EvaluationRunner(
        proxy=proxy,
        mock_tools=mock_tools,
        provenance_tracker=provenance_tracker,
        output_dir=args.out,
        seed=args.seed
    )
    
    metrics = runner.run_suite(suite)
    metrics.print_summary()
    
    # Additional attack-specific analysis
    print(f"\n=== Attack Analysis ===")
    print(f"Attack Success Rate (ASR): {metrics.asr:.2%}")
    print(f"Successful Attacks: {metrics.attacks_succeeded}/{metrics.attack_tasks}")
    print(f"Blocked Attacks: {metrics.attack_tasks - metrics.attacks_succeeded}/{metrics.attack_tasks}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

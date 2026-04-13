"""Main CLI entry point for running benchmark suites."""

import argparse
import sys

from provsafe.bench import BenchmarkSuite, MockToolRegistry
from provsafe.proxy import ToolRegistry, ToolSchema, ToolActionSchema, RiskTier, ToolCallProxy
from provsafe.policy import CapabilityPolicy, PolicyEngine
from provsafe.provenance import ProvenanceTracker
from provsafe.eval import EvaluationRunner


def setup_tool_schemas(registry: ToolRegistry):
    """Register standard tool schemas."""

    # File system tool
    fs_schema = ToolSchema(
        name="file_system",
        description="File system operations",
        actions=[
            ToolActionSchema(action="read", description="Read file", risk_tier=RiskTier.LOW),
            ToolActionSchema(action="write", description="Write file", risk_tier=RiskTier.MEDIUM),
            ToolActionSchema(action="delete", description="Delete file", risk_tier=RiskTier.HIGH),
            ToolActionSchema(action="list", description="List files", risk_tier=RiskTier.LOW),
        ],
    )
    registry.register(fs_schema)

    # Calendar tool
    cal_schema = ToolSchema(
        name="calendar",
        description="Calendar operations",
        actions=[
            ToolActionSchema(
                action="read", description="Read calendar event", risk_tier=RiskTier.LOW
            ),
            ToolActionSchema(
                action="create", description="Create event", risk_tier=RiskTier.MEDIUM
            ),
            ToolActionSchema(
                action="delete", description="Delete event", risk_tier=RiskTier.MEDIUM
            ),
            ToolActionSchema(action="list", description="List events", risk_tier=RiskTier.LOW),
        ],
    )
    registry.register(cal_schema)

    # Notification tool
    notif_schema = ToolSchema(
        name="notification",
        description="Send notifications",
        actions=[
            ToolActionSchema(
                action="send", description="Send notification", risk_tier=RiskTier.MEDIUM
            ),
            ToolActionSchema(
                action="list", description="List notifications", risk_tier=RiskTier.LOW
            ),
        ],
    )
    registry.register(notif_schema)

    # Email tool
    email_schema = ToolSchema(
        name="email",
        description="Email operations",
        actions=[
            ToolActionSchema(action="send", description="Send email", risk_tier=RiskTier.HIGH),
            ToolActionSchema(action="list", description="List emails", risk_tier=RiskTier.LOW),
        ],
    )
    registry.register(email_schema)


def main():
    parser = argparse.ArgumentParser(description="Run PROVSAFE benchmark suite")
    parser.add_argument("--suite", required=True, help="Path to benchmark suite YAML file")
    parser.add_argument("--policy", required=True, help="Path to policy YAML file")
    parser.add_argument("--out", required=True, help="Output directory for results")
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for determinism (default: 42)"
    )

    args = parser.parse_args()

    # Load suite
    print(f"Loading benchmark suite: {args.suite}")
    suite = BenchmarkSuite.from_yaml(args.suite)

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
        provenance_tracker=provenance_tracker,
    )

    mock_tools = MockToolRegistry(seed=args.seed)

    # Run evaluation
    runner = EvaluationRunner(
        proxy=proxy,
        mock_tools=mock_tools,
        provenance_tracker=provenance_tracker,
        output_dir=args.out,
        seed=args.seed,
    )

    metrics = runner.run_suite(suite)
    metrics.print_summary()

    return 0


if __name__ == "__main__":
    sys.exit(main())

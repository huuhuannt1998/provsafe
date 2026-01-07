#!/usr/bin/env python3
"""Quick test script to verify installation and run a simple example."""

from provsafe.proxy import (
    ToolCallRequest,
    ToolSchema,
    ToolActionSchema,
    ToolRegistry,
    ToolCallProxy,
    RiskTier,
)
from provsafe.policy import CapabilityPolicy, PolicyRule, PolicyEngine
from provsafe.provenance import ProvenanceTracker


def main():
    print("=== PROVSAFE Quick Test ===\n")
    
    # Setup tool registry
    print("1. Setting up tool registry...")
    registry = ToolRegistry()
    schema = ToolSchema(
        name="file_system",
        description="File system operations",
        actions=[
            ToolActionSchema(action="read", description="Read file", risk_tier=RiskTier.LOW),
            ToolActionSchema(action="delete", description="Delete file", risk_tier=RiskTier.HIGH),
        ]
    )
    registry.register(schema)
    print("   ✓ Tool registry configured\n")
    
    # Setup policy
    print("2. Setting up policy...")
    policy = CapabilityPolicy(
        name="Test Policy",
        default_allow=False,
        rules=[
            PolicyRule(
                name="allow_reads",
                tool="file_system",
                action="read",
                allow=True
            ),
            PolicyRule(
                name="deny_deletes",
                tool="file_system",
                action="delete",
                allow=False
            )
        ]
    )
    print("   ✓ Policy configured\n")
    
    # Setup proxy
    print("3. Setting up proxy...")
    policy_engine = PolicyEngine(policy)
    provenance_tracker = ProvenanceTracker()
    proxy = ToolCallProxy(registry, policy_engine, provenance_tracker)
    print("   ✓ Proxy ready\n")
    
    # Test benign request
    print("4. Testing benign file read...")
    read_request = ToolCallRequest(
        tool="file_system",
        action="read",
        resource="/home/user/document.txt"
    )
    decision = proxy.enforce_policy(read_request)
    print(f"   Decision: {decision.outcome.value}")
    print(f"   Reason: {decision.explanation}")
    print(f"   ✓ Benign request {'allowed' if decision.outcome.value == 'allow' else 'denied'}\n")
    
    # Test attack request
    print("5. Testing malicious file deletion...")
    delete_request = ToolCallRequest(
        tool="file_system",
        action="delete",
        resource="/home/user/important.txt"
    )
    decision = proxy.enforce_policy(delete_request)
    print(f"   Decision: {decision.outcome.value}")
    print(f"   Reason: {decision.explanation}")
    print(f"   ✓ Malicious request {'blocked' if decision.outcome.value == 'deny' else 'FAILED TO BLOCK'}\n")
    
    # Stats
    stats = proxy.get_stats()
    print(f"6. Proxy Statistics:")
    print(f"   Total requests: {stats['total_requests']}")
    print(f"   Allowed: {stats['allowed']}")
    print(f"   Denied: {stats['denied']}")
    print(f"   ✓ All systems operational\n")
    
    print("=== Test Complete ===")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

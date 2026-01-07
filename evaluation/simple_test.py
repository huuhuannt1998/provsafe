#!/usr/bin/env python3
"""
Simple end-to-end test of PROVSAFE without LLM.
"""

import sys
sys.path.insert(0, '../src')

from provenance_graph import ProvenanceGraph, TrustLabel
from policy_engine import PolicyEngine, RiskTier
from enforcement_proxy import EnforcementProxy
from tools import SmartThingsTools, FileSystemTools

def simple_test():
    print("=" * 70)
    print("PROVSAFE SIMPLE TEST")
    print("=" * 70)
    print()
    
    # Setup
    print("Setting up PROVSAFE...")
    provenance = ProvenanceGraph()
    config = {
        "risk_tiers": {
            "LOW": ["device.list"],
            "MEDIUM": ["switch.on"],
            "HIGH": ["fs.delete"],
        },
        "disable_rate_limiting": True,  # Disable for testing
    }
    policy_engine = PolicyEngine(config=config)
    
    st_tools = SmartThingsTools(mock_mode=True)
    fs_tools = FileSystemTools()
    
    tools = {
        "device.list": st_tools.device_list,
        "switch.on": st_tools.switch_on,
        "fs.delete": fs_tools.fs_delete,
    }
    
    proxy = EnforcementProxy(
        provenance_graph=provenance,
        policy_engine=policy_engine,
        tool_registry=tools,
        confirmation_handler=lambda **kwargs: False,  # Always deny confirmations
    )
    print("✓ Setup complete\n")
    
    # Test 1: Simple benign operation
    print("Test 1: List devices (LOW risk, no untrusted data)")
    print("-" * 70)
    
    user_node = provenance.add_user_input("List my devices")
    llm_node = provenance.add_llm_generation(
        llm_output='{"tool": "device.list", "arguments": {}}',
        source_node_ids=[user_node],
    )
    
    result1 = proxy.intercept_tool_call(
        tool_name="device.list",
        tool_args={},
        llm_reasoning_node_id=llm_node,
        metadata={},
    )
    
    print(f"Decision: {result1['execution_result']}")
    print(f"Allowed: {result1['allowed']}")
    if result1['allowed']:
        devices = result1['result']
        print(f"Result: Found {len(devices)} devices")
        print(f"  - {devices[0]['label']} ({devices[0]['deviceId']})")
    else:
        print(f"Reason: {result1['reason']}")
    print()
    
    # Test 2: Operation with confirmation
    print("Test 2: Delete file (HIGH risk)")
    print("-" * 70)
    
    user_node2 = provenance.add_user_input("Delete important.txt")
    llm_node2 = provenance.add_llm_generation(
        llm_output='{"tool": "fs.delete", "arguments": {"path": "important.txt"}}',
        source_node_ids=[user_node2],
    )
    
    result2 = proxy.intercept_tool_call(
        tool_name="fs.delete",
        tool_args={"path": "important.txt"},
        llm_reasoning_node_id=llm_node2,
        metadata={},
    )
    
    print(f"Decision: {result2['execution_result']}")
    print(f"Allowed: {result2['allowed']}")
    print(f"Reason: {result2['reason']}")
    print()
    
    # Statistics
    print("=" * 70)
    stats = proxy.get_statistics()
    print(f"Total calls: {stats['total_calls']}")
    print(f"Allowed: {stats['allowed']}, Denied: {stats['denied']}")
    print(f"Provenance nodes: {len(provenance.nodes)}")
    print("=" * 70)
    
    if result1['allowed'] and not result2['allowed']:
        print("\n✓ PROVSAFE WORKING CORRECTLY!")
        return 0
    else:
        print("\n✗ UNEXPECTED RESULTS")
        return 1

if __name__ == "__main__":
    sys.exit(simple_test())

#!/usr/bin/env python3
"""
Quick test to verify PROVSAFE real evaluation setup
"""

import sys
import os

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'evaluation'))

from provenance_graph import ProvenanceGraph
from policy_engine import PolicyEngine
from enforcement_proxy import EnforcementProxy
from llm_agent import LLMAgent, ToolRegistry
from tools import SmartThingsTools, FileSystemTools
import config

print("="*60)
print("PROVSAFE Setup Test")
print("="*60)

# 1. Test configuration
print("\n1. Testing configuration...")
print(f"   LLM API URL: {config.OPENWEBUI_URL}")
print(f"   Models available: {len(config.AGENT_MODELS)}")
for model in config.AGENT_MODELS:
    print(f"     - {model}")
print("   ✓ Configuration loaded")

# 2. Test provenance graph
print("\n2. Testing provenance graph...")
prov = ProvenanceGraph()
user_id = prov.add_user_input("Test input")
tool_id = prov.add_tool_result("device.list", [{"name": "Test"}], False)
llm_id = prov.add_llm_generation("Test output", [user_id, tool_id])
query = prov.query_provenance(llm_id)
print(f"   ✓ Provenance tracking: {query['is_untrusted']}")

# 3. Test policy engine
print("\n3. Testing policy engine...")
engine = PolicyEngine(config.POLICY_CONFIG)
result = engine.evaluate("switch.on", {"device_id": "test"}, {"has_untrusted_args": False})
print(f"   ✓ Policy evaluation: {result.decision.value}")

# 4. Test tools
print("\n4. Testing tools...")
st = SmartThingsTools(mock_mode=True)
devices = st.device_list()
print(f"   ✓ SmartThings tools: {len(devices)} mock devices")

fs = FileSystemTools()
files = fs.fs_list(".")
print(f"   ✓ FileSystem tools: {len(files)} files in sandbox")

# 5. Test enforcement proxy
print("\n5. Testing enforcement proxy...")
tool_registry = ToolRegistry()
tool_registry.register("device.list", "List devices", {}, st.device_list, "LOW")
proxy = EnforcementProxy(
    provenance_graph=prov,
    policy_engine=engine,
    tool_registry=tool_registry.get_tool_registry_dict(),
)
print("   ✓ Enforcement proxy initialized")

# 6. Test LLM agent setup (without calling API yet)
print("\n6. Testing LLM agent setup...")
agent = LLMAgent(
    model=config.AGENT_MODELS[0],
    api_url=config.OPENWEBUI_URL,
    api_key=config.OPENWEBUI_API_KEY,
    provenance=prov,
    enforcement_proxy=proxy,
    tools=tool_registry.get_tool_definitions(),
    max_iterations=3,
    temperature=0.0,
)
print(f"   ✓ LLM agent initialized with model: {config.AGENT_MODELS[0]}")

print("\n" + "="*60)
print("✓ ALL COMPONENTS READY FOR REAL EVALUATION!")
print("="*60)

print("\nNext steps:")
print("1. Run test scenario:   python3 evaluation/run_test_scenario.py")
print("2. Run full evaluation: python3 src/real_evaluation.py --model MODEL --scenarios FILE")

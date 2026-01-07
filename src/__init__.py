"""
PROVSAFE: Provenance-Verified Capability Sandboxing for Tool-Using LLM Agents

Core components:
- ProvenanceGraph: DAG tracking with trust labels
- PolicyEngine: Declarative policy evaluation
- EnforcementProxy: Tool call interception and enforcement
- LLMAgent: LLM agent wrapper with PROVSAFE integration
"""

from .provenance_graph import ProvenanceGraph, TrustLabel, ProvenanceNode
from .policy_engine import PolicyEngine, PolicyDecision, RiskTier, PolicyEvaluationResult
from .enforcement_proxy import EnforcementProxy, ExecutionResult, ToolCallLog
from .llm_agent import LLMAgent, ToolRegistry, ToolDefinition
from .tools import SmartThingsTools, FileSystemTools

__version__ = "1.0.0"

__all__ = [
    "ProvenanceGraph",
    "TrustLabel",
    "ProvenanceNode",
    "PolicyEngine",
    "PolicyDecision",
    "RiskTier",
    "PolicyEvaluationResult",
    "EnforcementProxy",
    "ExecutionResult",
    "ToolCallLog",
    "LLMAgent",
    "ToolRegistry",
    "ToolDefinition",
    "SmartThingsTools",
    "FileSystemTools",
]

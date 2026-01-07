"""Provenance tracking and logging."""

from typing import Dict, Any, Optional, List
from datetime import datetime
import json

from .graph import ProvenanceGraph, ProvenanceNode, NodeType, TrustLabel
from ..proxy.schema import ToolCallRequest, PolicyDecision


class ProvenanceTracker:
    """
    Tracks provenance of tool calls and their justifications.
    
    Links tool calls to the source inputs (trusted/untrusted)
    that led to them, enabling integrity verification.
    """
    
    def __init__(self):
        self.graph = ProvenanceGraph()
        self._session_context: Dict[str, Any] = {}
    
    def add_input(
        self,
        content: Dict[str, Any],
        trust_label: TrustLabel,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add an input node (e.g., user message, API response).
        
        Returns:
            node_id of created node
        """
        node = ProvenanceNode.create(
            node_type=NodeType.INPUT,
            content=content,
            trust_label=trust_label,
            metadata=metadata
        )
        self.graph.add_node(node)
        return node.node_id
    
    def add_derived_fact(
        self,
        content: Dict[str, Any],
        parent_ids: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add a derived fact (e.g., extracted info, reasoning step).
        
        Args:
            content: Fact content
            parent_ids: Parent node IDs this fact derives from
            metadata: Additional metadata
            
        Returns:
            node_id of created node
        """
        # Inherit trust label from parents
        parent_nodes = [self.graph.get_node(pid) for pid in parent_ids]
        if any(n and n.trust_label == TrustLabel.UNTRUSTED for n in parent_nodes):
            trust_label = TrustLabel.UNTRUSTED
        elif all(n and n.trust_label == TrustLabel.TRUSTED for n in parent_nodes if n):
            trust_label = TrustLabel.TRUSTED
        else:
            trust_label = TrustLabel.UNKNOWN
        
        node = ProvenanceNode.create(
            node_type=NodeType.DERIVED_FACT,
            content=content,
            trust_label=trust_label,
            parents=parent_ids,
            metadata=metadata
        )
        self.graph.add_node(node)
        return node.node_id
    
    def log_tool_call(
        self,
        request: ToolCallRequest,
        decision: PolicyDecision,
        timestamp: datetime,
        parent_ids: Optional[List[str]] = None
    ) -> str:
        """
        Log a tool call with its policy decision.
        
        Args:
            request: Tool call request
            decision: Policy decision
            timestamp: When the call was made
            parent_ids: Input/fact nodes that justified this call
            
        Returns:
            node_id of tool call node
        """
        content = {
            "tool": request.tool,
            "action": request.action,
            "resource": request.resource,
            "args": request.args,
            "decision": decision.outcome.value,
            "reason_code": decision.reason_code.value,
        }
        
        metadata = {
            "matched_rule": decision.matched_rule,
            "risk_tier": decision.risk_tier.value if decision.risk_tier else None,
            "timestamp": timestamp.isoformat(),
        }
        
        node = ProvenanceNode.create(
            node_type=NodeType.TOOL_CALL,
            content=content,
            trust_label=TrustLabel.UNKNOWN,  # Tool calls don't have inherent trust
            parents=parent_ids or [],
            metadata=metadata
        )
        self.graph.add_node(node)
        return node.node_id
    
    def add_effect(
        self,
        content: Dict[str, Any],
        tool_call_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add an effect node (observable outcome of tool call).
        
        Args:
            content: Effect description
            tool_call_id: Tool call that produced this effect
            metadata: Additional metadata
            
        Returns:
            node_id of effect node
        """
        node = ProvenanceNode.create(
            node_type=NodeType.EFFECT,
            content=content,
            trust_label=TrustLabel.UNKNOWN,
            parents=[tool_call_id],
            metadata=metadata
        )
        self.graph.add_node(node)
        return node.node_id
    
    def get_provenance_summary(self, node_id: str) -> Dict[str, Any]:
        """
        Get provenance summary for a node.
        
        Returns:
            Summary including trust sources, derivation depth, etc.
        """
        trust_counts = self.graph.get_trust_sources(node_id)
        derivation_depth = self.graph.compute_derivation_depth(node_id)
        
        return {
            "node_id": node_id,
            "trusted_sources": trust_counts[TrustLabel.TRUSTED],
            "untrusted_sources": trust_counts[TrustLabel.UNTRUSTED],
            "derivation_depth": derivation_depth,
            "total_ancestors": len(self.graph.get_ancestors(node_id)),
        }
    
    def export_graph(self) -> Dict[str, Any]:
        """Export full provenance graph."""
        return self.graph.to_dict()
    
    def save_to_file(self, filepath: str):
        """Save provenance graph to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.export_graph(), f, indent=2, default=str)
    
    @classmethod
    def load_from_file(cls, filepath: str) -> "ProvenanceTracker":
        """Load provenance graph from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        tracker = cls()
        tracker.graph = ProvenanceGraph.from_dict(data)
        return tracker

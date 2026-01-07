#!/usr/bin/env python3
"""
PROVSAFE Provenance Graph Implementation

Tracks data flow through the LLM agent using a Directed Acyclic Graph (DAG).
Each node represents a piece of information with a trust label (trusted/untrusted).
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Any
import uuid


class TrustLabel(Enum):
    """Trust labels for provenance nodes."""
    TRUSTED = "trusted"      # User input, system config
    UNTRUSTED = "untrusted"  # External data (devices, files, web)
    DERIVED = "derived"      # LLM-generated, inherits from sources


@dataclass
class ProvenanceNode:
    """A node in the provenance DAG representing a piece of information."""
    node_id: str
    source_type: str  # "user_input", "tool_result", "llm_generation", etc.
    trust_label: TrustLabel
    content: Any
    timestamp: datetime
    parent_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize node to dictionary."""
        return {
            "node_id": self.node_id,
            "source_type": self.source_type,
            "trust_label": self.trust_label.value,
            "content": str(self.content)[:500],  # Truncate for logging
            "timestamp": self.timestamp.isoformat(),
            "parent_ids": self.parent_ids,
            "metadata": self.metadata,
        }
    
    def content_hash(self) -> str:
        """Compute SHA-256 hash of content for integrity verification."""
        content_str = json.dumps(self.content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()


class ProvenanceGraph:
    """
    Directed Acyclic Graph tracking data provenance with trust propagation.
    
    Key operations:
    - add_user_input(): Mark user commands as TRUSTED
    - add_tool_result(): Mark external data as UNTRUSTED
    - add_llm_generation(): DERIVED, inherits trust from sources
    - query_provenance(): Trace back to determine if any ancestor is UNTRUSTED
    """
    
    def __init__(self):
        self.nodes: Dict[str, ProvenanceNode] = {}
        self.edges: Dict[str, List[str]] = {}  # node_id -> [child_ids]
        
    def add_node(
        self,
        source_type: str,
        trust_label: TrustLabel,
        content: Any,
        parent_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add a node to the provenance graph.
        
        Args:
            source_type: Type of source (e.g., "user_input", "tool_result")
            trust_label: TRUSTED, UNTRUSTED, or DERIVED
            content: The actual data/information
            parent_ids: IDs of nodes this was derived from
            metadata: Additional context (tool name, arguments, etc.)
            
        Returns:
            node_id: Unique identifier for the new node
        """
        node_id = str(uuid.uuid4())
        parent_ids = parent_ids or []
        metadata = metadata or {}
        
        # Create node
        node = ProvenanceNode(
            node_id=node_id,
            source_type=source_type,
            trust_label=trust_label,
            content=content,
            timestamp=datetime.now(),
            parent_ids=parent_ids,
            metadata=metadata,
        )
        
        self.nodes[node_id] = node
        
        # Add edges from parents to this node
        for parent_id in parent_ids:
            if parent_id not in self.edges:
                self.edges[parent_id] = []
            self.edges[parent_id].append(node_id)
        
        return node_id
    
    def add_user_input(self, user_message: str, metadata: Optional[Dict] = None) -> str:
        """Add user input as TRUSTED."""
        return self.add_node(
            source_type="user_input",
            trust_label=TrustLabel.TRUSTED,
            content=user_message,
            parent_ids=[],
            metadata=metadata or {},
        )
    
    def add_tool_result(
        self,
        tool_name: str,
        tool_output: Any,
        is_trusted_tool: bool = False,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Add tool execution result.
        
        Args:
            tool_name: Name of the tool executed
            tool_output: Output returned by the tool
            is_trusted_tool: If True, mark as TRUSTED (e.g., system config)
            metadata: Additional context
        """
        trust_label = TrustLabel.TRUSTED if is_trusted_tool else TrustLabel.UNTRUSTED
        
        meta = metadata or {}
        meta["tool_name"] = tool_name
        
        return self.add_node(
            source_type="tool_result",
            trust_label=trust_label,
            content=tool_output,
            parent_ids=[],
            metadata=meta,
        )
    
    def add_llm_generation(
        self,
        llm_output: Any,
        source_node_ids: List[str],
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Add LLM-generated content that was derived from source nodes.
        Trust label is DERIVED and inherits untrusted status from any ancestor.
        
        Args:
            llm_output: Content generated by LLM
            source_node_ids: Nodes that were in the LLM's context
            metadata: Additional context
        """
        # Check if any source is untrusted
        has_untrusted_source = any(
            self.is_untrusted(node_id) for node_id in source_node_ids
        )
        
        trust_label = TrustLabel.UNTRUSTED if has_untrusted_source else TrustLabel.DERIVED
        
        return self.add_node(
            source_type="llm_generation",
            trust_label=trust_label,
            content=llm_output,
            parent_ids=source_node_ids,
            metadata=metadata or {},
        )
    
    def add_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        reasoning_node_id: str,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Add a tool call proposed by the LLM.
        
        Args:
            tool_name: Tool being called
            arguments: Tool arguments
            reasoning_node_id: LLM generation that produced this tool call
            metadata: Additional context
        """
        meta = metadata or {}
        meta["tool_name"] = tool_name
        meta["arguments"] = arguments
        
        return self.add_node(
            source_type="tool_call",
            trust_label=TrustLabel.DERIVED,
            content={"tool": tool_name, "args": arguments},
            parent_ids=[reasoning_node_id],
            metadata=meta,
        )
    
    def query_provenance(self, node_id: str) -> Dict[str, Any]:
        """
        Query provenance for a node, returning all ancestors and trust status.
        
        Returns:
            {
                "node": ProvenanceNode,
                "is_untrusted": bool,
                "untrusted_ancestors": List[ProvenanceNode],
                "all_ancestors": List[ProvenanceNode],
                "trust_path": List[str],  # Trace from node to untrusted sources
            }
        """
        if node_id not in self.nodes:
            raise ValueError(f"Node {node_id} not found in graph")
        
        node = self.nodes[node_id]
        ancestors = self._get_all_ancestors(node_id)
        untrusted_ancestors = [
            self.nodes[aid] for aid in ancestors
            if self.nodes[aid].trust_label == TrustLabel.UNTRUSTED
        ]
        
        # Find shortest path to an untrusted ancestor
        trust_path = []
        if untrusted_ancestors:
            trust_path = self._find_trust_path(node_id, untrusted_ancestors[0].node_id)
        
        return {
            "node": node,
            "is_untrusted": len(untrusted_ancestors) > 0 or node.trust_label == TrustLabel.UNTRUSTED,
            "untrusted_ancestors": untrusted_ancestors,
            "all_ancestors": [self.nodes[aid] for aid in ancestors],
            "trust_path": trust_path,
        }
    
    def is_untrusted(self, node_id: str) -> bool:
        """Check if a node or any of its ancestors is untrusted."""
        if node_id not in self.nodes:
            return False
        
        node = self.nodes[node_id]
        if node.trust_label == TrustLabel.UNTRUSTED:
            return True
        
        # Check ancestors
        ancestors = self._get_all_ancestors(node_id)
        return any(
            self.nodes[aid].trust_label == TrustLabel.UNTRUSTED
            for aid in ancestors
        )
    
    def trace_argument_provenance(self, tool_call_args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trace provenance of tool call arguments by analyzing their values.
        
        This is a heuristic approach: we search for nodes whose content matches
        the argument values, then trace their provenance.
        
        Returns:
            {
                "has_untrusted_args": bool,
                "untrusted_arg_names": List[str],
                "provenance_by_arg": Dict[str, Dict],
            }
        """
        provenance_by_arg = {}
        untrusted_arg_names = []
        
        for arg_name, arg_value in tool_call_args.items():
            # Find nodes whose content contains this value
            matching_nodes = self._find_nodes_containing(arg_value)
            
            if matching_nodes:
                # Use the most recent matching node
                node_id = matching_nodes[0]
                prov = self.query_provenance(node_id)
                provenance_by_arg[arg_name] = prov
                
                if prov["is_untrusted"]:
                    untrusted_arg_names.append(arg_name)
            else:
                # No provenance found - assume trusted (user-provided literal)
                provenance_by_arg[arg_name] = {"is_untrusted": False}
        
        return {
            "has_untrusted_args": len(untrusted_arg_names) > 0,
            "untrusted_arg_names": untrusted_arg_names,
            "provenance_by_arg": provenance_by_arg,
        }
    
    def _get_all_ancestors(self, node_id: str) -> Set[str]:
        """BFS to get all ancestor node IDs."""
        ancestors = set()
        queue = [node_id]
        visited = set()
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            if current in self.nodes:
                node = self.nodes[current]
                for parent_id in node.parent_ids:
                    if parent_id not in visited:
                        ancestors.add(parent_id)
                        queue.append(parent_id)
        
        return ancestors
    
    def _find_trust_path(self, from_node: str, to_node: str) -> List[str]:
        """Find shortest path from from_node to to_node."""
        if from_node == to_node:
            return [from_node]
        
        queue = [(from_node, [from_node])]
        visited = set()
        
        while queue:
            current, path = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            if current == to_node:
                return path
            
            if current in self.nodes:
                node = self.nodes[current]
                for parent_id in node.parent_ids:
                    if parent_id not in visited:
                        queue.append((parent_id, path + [parent_id]))
        
        return []
    
    def _find_nodes_containing(self, value: Any, max_results: int = 5) -> List[str]:
        """Find nodes whose content contains the given value."""
        matching = []
        value_str = str(value).lower()
        
        # Search in reverse chronological order (most recent first)
        sorted_nodes = sorted(
            self.nodes.items(),
            key=lambda x: x[1].timestamp,
            reverse=True
        )
        
        for node_id, node in sorted_nodes:
            content_str = str(node.content).lower()
            if value_str in content_str or content_str in value_str:
                matching.append(node_id)
                if len(matching) >= max_results:
                    break
        
        return matching
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the provenance graph."""
        trust_counts = {
            TrustLabel.TRUSTED: 0,
            TrustLabel.UNTRUSTED: 0,
            TrustLabel.DERIVED: 0,
        }
        
        for node in self.nodes.values():
            trust_counts[node.trust_label] += 1
        
        return {
            "total_nodes": len(self.nodes),
            "total_edges": sum(len(children) for children in self.edges.values()),
            "trusted_nodes": trust_counts[TrustLabel.TRUSTED],
            "untrusted_nodes": trust_counts[TrustLabel.UNTRUSTED],
            "derived_nodes": trust_counts[TrustLabel.DERIVED],
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize entire graph to dictionary."""
        return {
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
            "edges": self.edges,
            "statistics": self.get_statistics(),
        }
    
    def export_to_json(self, filepath: str):
        """Export graph to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

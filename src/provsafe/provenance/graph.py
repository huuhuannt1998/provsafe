"""Provenance graph data structures."""

from typing import Dict, Any, List, Optional, Set
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field
import hashlib
import json


class NodeType(str, Enum):
    """Types of provenance nodes."""
    INPUT = "input"  # User input or external data
    DERIVED_FACT = "derived_fact"  # Fact derived from inputs
    TOOL_CALL = "tool_call"  # Tool invocation
    EFFECT = "effect"  # Observable effect/output


class TrustLabel(str, Enum):
    """Trust classification for inputs."""
    TRUSTED = "trusted"  # From verified source
    UNTRUSTED = "untrusted"  # From unverified source (e.g., user input)
    UNKNOWN = "unknown"  # Trust not yet determined


class ProvenanceNode(BaseModel):
    """Single node in the provenance graph."""
    node_id: str = Field(..., description="Unique node identifier")
    node_type: NodeType
    timestamp: datetime
    
    # Content
    content: Dict[str, Any] = Field(default_factory=dict)
    content_hash: str = Field(..., description="Hash of content for integrity")
    
    # Trust and metadata
    trust_label: TrustLabel = TrustLabel.UNKNOWN
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Graph edges (parent node IDs)
    parents: List[str] = Field(default_factory=list)
    
    @classmethod
    def create(
        cls,
        node_type: NodeType,
        content: Dict[str, Any],
        trust_label: TrustLabel = TrustLabel.UNKNOWN,
        parents: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "ProvenanceNode":
        """Create a new provenance node with computed hash."""
        content_str = json.dumps(content, sort_keys=True)
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()[:16]
        
        node_id = f"{node_type.value}_{int(datetime.now().timestamp() * 1000)}_{content_hash[:8]}"
        
        return cls(
            node_id=node_id,
            node_type=node_type,
            timestamp=datetime.now(),
            content=content,
            content_hash=content_hash,
            trust_label=trust_label,
            metadata=metadata or {},
            parents=parents or []
        )


class ProvenanceEdge(BaseModel):
    """Edge in provenance graph."""
    source_id: str
    target_id: str
    edge_type: str = "derives_from"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProvenanceGraph(BaseModel):
    """Complete provenance graph."""
    nodes: Dict[str, ProvenanceNode] = Field(default_factory=dict)
    edges: List[ProvenanceEdge] = Field(default_factory=list)
    
    def add_node(self, node: ProvenanceNode):
        """Add a node to the graph."""
        self.nodes[node.node_id] = node
        
        # Create edges from parents
        for parent_id in node.parents:
            self.edges.append(ProvenanceEdge(
                source_id=parent_id,
                target_id=node.node_id
            ))
    
    def get_node(self, node_id: str) -> Optional[ProvenanceNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def get_ancestors(self, node_id: str, max_depth: Optional[int] = None) -> Set[str]:
        """Get all ancestor node IDs (parents, grandparents, etc.)."""
        ancestors = set()
        current_depth = 0
        frontier = {node_id}
        
        while frontier and (max_depth is None or current_depth < max_depth):
            next_frontier = set()
            for nid in frontier:
                node = self.get_node(nid)
                if node:
                    for parent_id in node.parents:
                        if parent_id not in ancestors:
                            ancestors.add(parent_id)
                            next_frontier.add(parent_id)
            frontier = next_frontier
            current_depth += 1
        
        return ancestors
    
    def get_trust_sources(self, node_id: str, max_depth: Optional[int] = None) -> Dict[TrustLabel, int]:
        """Get count of trusted/untrusted sources in ancestry."""
        ancestor_ids = self.get_ancestors(node_id, max_depth)
        ancestor_ids.add(node_id)
        
        counts = {TrustLabel.TRUSTED: 0, TrustLabel.UNTRUSTED: 0, TrustLabel.UNKNOWN: 0}
        
        for aid in ancestor_ids:
            node = self.get_node(aid)
            if node:
                counts[node.trust_label] += 1
        
        return counts
    
    def compute_derivation_depth(self, node_id: str) -> int:
        """Compute maximum derivation depth from trusted inputs."""
        node = self.get_node(node_id)
        if not node:
            return 0
        
        if node.trust_label == TrustLabel.TRUSTED:
            return 0
        
        if not node.parents:
            return 0
        
        max_parent_depth = max(
            (self.compute_derivation_depth(pid) for pid in node.parents),
            default=0
        )
        
        return max_parent_depth + 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to dictionary."""
        return {
            "nodes": {nid: node.model_dump(mode='json') for nid, node in self.nodes.items()},
            "edges": [edge.model_dump() for edge in self.edges]
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProvenanceGraph":
        """Deserialize graph from dictionary."""
        nodes = {
            nid: ProvenanceNode(**node_data)
            for nid, node_data in data.get("nodes", {}).items()
        }
        edges = [ProvenanceEdge(**edge_data) for edge_data in data.get("edges", [])]
        return cls(nodes=nodes, edges=edges)

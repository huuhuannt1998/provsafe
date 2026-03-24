"""Provenance graph data structures adapted from W3C PROV-DM.

Formal model:  G = (V, E, T, τ)
  V  – provenance nodes (PROV-DM Entities / Activities)
  E  ⊆ V × V – derivation edges (wasDerivedFrom, wasGeneratedBy, used)
  T  : V → L – trust label from lattice L = {⊤ (TRUSTED), ⊥ (UNTRUSTED)}
  τ  : V → ℕ – creation timestamp

References:
  - W3C PROV-DM: https://www.w3.org/TR/prov-dm/
  - Why-provenance: Buneman et al., ICDT 2001
  - Provenance semirings: Green et al., PODS 2007
"""

from typing import Dict, Any, List, Optional, Set
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field
import hashlib
import json


class NodeType(str, Enum):
    """Types of provenance nodes (PROV-DM entity sub-types).

    Mapping to PROV-DM:
      INPUT        → prov:Entity  (primary source)
      DERIVED_FACT → prov:Entity  (wasDerivedFrom other entities)
      TOOL_CALL    → prov:Activity (proposed tool invocation)
      EFFECT       → prov:Entity  (wasGeneratedBy an Activity)
    """
    INPUT = "input"            # prov:Entity (primary source)
    DERIVED_FACT = "derived_fact"  # prov:Entity (derived)
    TOOL_CALL = "tool_call"    # prov:Activity
    EFFECT = "effect"          # prov:Entity (generated)


class ProvDMRelation(str, Enum):
    """PROV-DM edge / relation types."""
    WAS_DERIVED_FROM = "wasDerivedFrom"   # Entity → Entity
    WAS_GENERATED_BY = "wasGeneratedBy"   # Entity → Activity
    USED = "used"                          # Activity → Entity


class TrustLabel(str, Enum):
    """Trust classification forming lattice L = {⊤, ⊥}.

    ⊤ (TRUSTED)   – from verified source (user, system config).
    ⊥ (UNTRUSTED) – from unverified source (tool output, external data).
    UNKNOWN       – not yet resolved (will be treated as ⊥ conservatively).
    """
    TRUSTED = "trusted"      # ⊤
    UNTRUSTED = "untrusted"  # ⊥
    UNKNOWN = "unknown"      # Treated as ⊥ in lattice operations


def trust_meet(*labels: TrustLabel) -> TrustLabel:
    """Lattice meet (⊓):  returns ⊥ if any label is UNTRUSTED or UNKNOWN."""
    for lbl in labels:
        if lbl in (TrustLabel.UNTRUSTED, TrustLabel.UNKNOWN):
            return TrustLabel.UNTRUSTED
    return TrustLabel.TRUSTED


class ProvenanceNode(BaseModel):
    """Single node in the provenance graph (PROV-DM Entity or Activity)."""
    node_id: str = Field(..., description="Unique node identifier")
    node_type: NodeType
    timestamp: datetime
    
    # Content
    content: Dict[str, Any] = Field(default_factory=dict)
    content_hash: str = Field(..., description="SHA-256 hash for integrity")
    
    # Trust and metadata
    trust_label: TrustLabel = TrustLabel.UNKNOWN
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Graph edges (parent node IDs) with PROV-DM relation types
    parents: List[str] = Field(default_factory=list)
    edge_types: Dict[str, str] = Field(
        default_factory=dict,
        description="parent_id → ProvDMRelation value"
    )
    
    @classmethod
    def create(
        cls,
        node_type: NodeType,
        content: Dict[str, Any],
        trust_label: TrustLabel = TrustLabel.UNKNOWN,
        parents: Optional[List[str]] = None,
        edge_relation: ProvDMRelation = ProvDMRelation.WAS_DERIVED_FROM,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "ProvenanceNode":
        """Create a new provenance node with computed hash and PROV-DM annotation."""
        content_str = json.dumps(content, sort_keys=True)
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()[:16]
        
        node_id = f"{node_type.value}_{int(datetime.now().timestamp() * 1000)}_{content_hash[:8]}"
        parents = parents or []
        edge_types = {pid: edge_relation.value for pid in parents}
        
        return cls(
            node_id=node_id,
            node_type=node_type,
            timestamp=datetime.now(),
            content=content,
            content_hash=content_hash,
            trust_label=trust_label,
            metadata=metadata or {},
            parents=parents,
            edge_types=edge_types,
        )


class ProvenanceEdge(BaseModel):
    """Edge in provenance graph (PROV-DM relation)."""
    source_id: str
    target_id: str
    edge_type: str = ProvDMRelation.WAS_DERIVED_FROM.value
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProvenanceGraph(BaseModel):
    """Complete provenance graph adapted from W3C PROV-DM.
    
    Formal model:  G = (V, E, T, τ)  where
      V = nodes, E = edges, T = trust labels from L = {⊤, ⊥}, τ = timestamps.
    """
    nodes: Dict[str, ProvenanceNode] = Field(default_factory=dict)
    edges: List[ProvenanceEdge] = Field(default_factory=list)
    
    def add_node(self, node: ProvenanceNode):
        """Add a node (PROV-DM Entity/Activity) to the graph."""
        self.nodes[node.node_id] = node
        
        # Create edges from parents with PROV-DM relation types
        for parent_id in node.parents:
            edge_type = node.edge_types.get(
                parent_id, ProvDMRelation.WAS_DERIVED_FROM.value
            )
            self.edges.append(ProvenanceEdge(
                source_id=parent_id,
                target_id=node.node_id,
                edge_type=edge_type,
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
        """Get count of trusted/untrusted sources in ancestry (why-provenance)."""
        ancestor_ids = self.get_ancestors(node_id, max_depth)
        ancestor_ids.add(node_id)
        
        counts = {TrustLabel.TRUSTED: 0, TrustLabel.UNTRUSTED: 0, TrustLabel.UNKNOWN: 0}
        
        for aid in ancestor_ids:
            node = self.get_node(aid)
            if node:
                counts[node.trust_label] += 1
        
        return counts
    
    def effective_trust(self, node_id: str) -> TrustLabel:
        """Compute effective trust via lattice meet over all ancestors.
        
        T(v) = ⊓_{u ∈ ancestors(v) ∪ {v}} T(u)
        """
        ancestor_ids = self.get_ancestors(node_id)
        ancestor_ids.add(node_id)
        
        labels = []
        for aid in ancestor_ids:
            node = self.get_node(aid)
            if node:
                labels.append(node.trust_label)
        
        return trust_meet(*labels) if labels else TrustLabel.UNTRUSTED
    
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
        """Serialize graph to dictionary (PROV-DM annotated)."""
        return {
            "prov_model": "PROV-DM (W3C Recommendation, 2013)",
            "lattice": "L = {TRUSTED (⊤), UNTRUSTED (⊥)}",
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

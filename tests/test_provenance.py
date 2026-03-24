"""Tests for provenance tracking."""

import pytest
from provsafe.provenance import (
    ProvenanceGraph,
    ProvenanceNode,
    ProvenanceTracker,
    NodeType,
    TrustLabel,
)
from provsafe.proxy import ToolCallRequest, PolicyDecision, DecisionOutcome, ReasonCode
from datetime import datetime


def test_provenance_node_creation():
    """Test creating provenance nodes."""
    node = ProvenanceNode.create(
        node_type=NodeType.INPUT,
        content={"message": "test input"},
        trust_label=TrustLabel.TRUSTED
    )
    
    assert node.node_type == NodeType.INPUT
    assert node.trust_label == TrustLabel.TRUSTED
    assert node.content["message"] == "test input"
    assert node.content_hash is not None


def test_provenance_graph_add_node():
    """Test adding nodes to provenance graph."""
    graph = ProvenanceGraph()
    
    node1 = ProvenanceNode.create(
        node_type=NodeType.INPUT,
        content={"data": "test"}
    )
    
    node2 = ProvenanceNode.create(
        node_type=NodeType.DERIVED_FACT,
        content={"fact": "derived"},
        parents=[node1.node_id]
    )
    
    graph.add_node(node1)
    graph.add_node(node2)
    
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert graph.edges[0].source_id == node1.node_id
    assert graph.edges[0].target_id == node2.node_id


def test_provenance_graph_get_ancestors():
    """Test getting ancestors in provenance graph."""
    graph = ProvenanceGraph()
    
    # Create a chain: node1 -> node2 -> node3
    node1 = ProvenanceNode.create(NodeType.INPUT, {"data": "1"})
    node2 = ProvenanceNode.create(NodeType.DERIVED_FACT, {"data": "2"}, parents=[node1.node_id])
    node3 = ProvenanceNode.create(NodeType.TOOL_CALL, {"data": "3"}, parents=[node2.node_id])
    
    graph.add_node(node1)
    graph.add_node(node2)
    graph.add_node(node3)
    
    ancestors = graph.get_ancestors(node3.node_id)
    assert node1.node_id in ancestors
    assert node2.node_id in ancestors
    assert len(ancestors) == 2


def test_provenance_graph_trust_sources():
    """Test counting trust sources."""
    graph = ProvenanceGraph()
    
    # Create nodes with different trust labels
    trusted = ProvenanceNode.create(NodeType.INPUT, {"data": "t"}, trust_label=TrustLabel.TRUSTED)
    untrusted = ProvenanceNode.create(NodeType.INPUT, {"data": "u"}, trust_label=TrustLabel.UNTRUSTED)
    derived = ProvenanceNode.create(
        NodeType.DERIVED_FACT,
        {"data": "d"},
        parents=[trusted.node_id, untrusted.node_id]
    )
    
    graph.add_node(trusted)
    graph.add_node(untrusted)
    graph.add_node(derived)
    
    trust_counts = graph.get_trust_sources(derived.node_id)
    assert trust_counts[TrustLabel.TRUSTED] == 1
    assert trust_counts[TrustLabel.UNTRUSTED] == 1


def test_provenance_tracker_add_input():
    """Test adding input nodes via tracker."""
    tracker = ProvenanceTracker()
    
    node_id = tracker.add_input(
        content={"message": "user input"},
        trust_label=TrustLabel.UNTRUSTED
    )
    
    assert node_id is not None
    node = tracker.graph.get_node(node_id)
    assert node.node_type == NodeType.INPUT
    assert node.trust_label == TrustLabel.UNTRUSTED


def test_provenance_tracker_log_tool_call():
    """Test logging tool calls."""
    tracker = ProvenanceTracker()
    
    input_id = tracker.add_input(
        content={"message": "test"},
        trust_label=TrustLabel.TRUSTED
    )
    
    request = ToolCallRequest(
        tool="file_system",
        action="read",
        resource="/test/path"
    )
    
    decision = PolicyDecision(
        outcome=DecisionOutcome.ALLOW,
        reason_code=ReasonCode.ALLOWED_BY_POLICY,
        explanation="Test"
    )
    
    tool_call_id = tracker.log_tool_call(
        request=request,
        decision=decision,
        timestamp=datetime.now(),
        parent_ids=[input_id]
    )
    
    assert tool_call_id is not None
    node = tracker.graph.get_node(tool_call_id)
    assert node.node_type == NodeType.TOOL_CALL
    assert input_id in node.parents


def test_provenance_tracker_summary():
    """Test getting provenance summary."""
    tracker = ProvenanceTracker()
    
    trusted_id = tracker.add_input(
        content={"data": "trusted"},
        trust_label=TrustLabel.TRUSTED
    )
    
    derived_id = tracker.add_derived_fact(
        content={"fact": "extracted"},
        parent_ids=[trusted_id]
    )
    
    summary = tracker.get_provenance_summary(derived_id)
    # Count includes the node itself + its ancestors
    assert summary["trusted_sources"] == 2  # derived node (inherits TRUSTED) + parent
    assert summary["untrusted_sources"] == 0
    assert summary["effective_trust"] == "trusted"

"""Tests for proxy module."""

import pytest
from provsafe.proxy import (
    ToolCallRequest,
    ToolSchema,
    ToolActionSchema,
    ToolRegistry,
    ToolCallProxy,
    RiskTier,
    DecisionOutcome,
)
from provsafe.policy import CapabilityPolicy, PolicyEngine


@pytest.fixture
def tool_registry():
    """Create a tool registry with test schemas."""
    registry = ToolRegistry()

    schema = ToolSchema(
        name="test_tool",
        description="Test tool",
        actions=[
            ToolActionSchema(action="read", description="Read", risk_tier=RiskTier.LOW),
            ToolActionSchema(action="write", description="Write", risk_tier=RiskTier.MEDIUM),
            ToolActionSchema(action="delete", description="Delete", risk_tier=RiskTier.HIGH),
        ],
    )
    registry.register(schema)
    return registry


@pytest.fixture
def simple_policy():
    """Create a simple allow-all policy."""
    return CapabilityPolicy(name="Test Policy", default_allow=True, rules=[])


def test_tool_registry_validation(tool_registry):
    """Test tool registry validates requests."""
    valid_request = ToolCallRequest(tool="test_tool", action="read", resource="/test/path")

    is_valid, error = tool_registry.validate_request(valid_request)
    assert is_valid
    assert error is None


def test_tool_registry_invalid_tool(tool_registry):
    """Test validation fails for unknown tool."""
    invalid_request = ToolCallRequest(tool="unknown_tool", action="read", resource="/test/path")

    is_valid, error = tool_registry.validate_request(invalid_request)
    assert not is_valid
    assert "Unknown tool" in error


def test_tool_registry_invalid_action(tool_registry):
    """Test validation fails for invalid action."""
    invalid_request = ToolCallRequest(
        tool="test_tool", action="invalid_action", resource="/test/path"
    )

    is_valid, error = tool_registry.validate_request(invalid_request)
    assert not is_valid
    assert "Invalid action" in error


def test_proxy_allows_valid_request(tool_registry, simple_policy):
    """Test proxy allows valid request with permissive policy."""
    policy_engine = PolicyEngine(simple_policy)
    proxy = ToolCallProxy(tool_registry=tool_registry, policy_engine=policy_engine)

    request = ToolCallRequest(tool="test_tool", action="read", resource="/test/path")

    decision = proxy.enforce_policy(request)
    assert decision.outcome == DecisionOutcome.ALLOW


def test_proxy_denies_invalid_schema(tool_registry, simple_policy):
    """Test proxy denies request that fails schema validation."""
    policy_engine = PolicyEngine(simple_policy)
    proxy = ToolCallProxy(tool_registry=tool_registry, policy_engine=policy_engine)

    request = ToolCallRequest(tool="unknown_tool", action="read", resource="/test/path")

    decision = proxy.enforce_policy(request)
    assert decision.outcome == DecisionOutcome.DENY


def test_proxy_tracks_stats(tool_registry, simple_policy):
    """Test proxy tracks statistics."""
    policy_engine = PolicyEngine(simple_policy)
    proxy = ToolCallProxy(tool_registry=tool_registry, policy_engine=policy_engine)

    request = ToolCallRequest(tool="test_tool", action="read", resource="/test/path")

    proxy.enforce_policy(request)
    proxy.enforce_policy(request)

    stats = proxy.get_stats()
    assert stats["total_requests"] == 2
    assert stats["allowed"] == 2

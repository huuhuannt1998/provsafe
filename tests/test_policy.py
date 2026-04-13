"""Tests for policy engine."""

import pytest
from datetime import time as time_type
from provsafe.policy import (
    CapabilityPolicy,
    PolicyRule,
    PolicyEngine,
    TimeConstraint,
    RateLimitConstraint,
)
from provsafe.proxy import ToolCallRequest, DecisionOutcome, RiskTier


@pytest.fixture
def basic_policy():
    """Create a basic policy with some rules."""
    return CapabilityPolicy(
        name="Test Policy",
        default_allow=False,
        rules=[
            PolicyRule(name="allow_reads", tool="*", action="read", allow=True),
            PolicyRule(name="deny_deletes", tool="*", action="delete", allow=False),
        ],
    )


def test_policy_matches_wildcard():
    """Test policy rule matches with wildcards."""
    rule = PolicyRule(name="test", tool="*", action="*", allow=True)

    assert rule.matches("any_tool", "any_action")
    assert rule.matches("file_system", "read")


def test_policy_matches_specific():
    """Test policy rule matches specific tool/action."""
    rule = PolicyRule(name="test", tool="file_system", action="read", allow=True)

    assert rule.matches("file_system", "read")
    assert not rule.matches("calendar", "read")
    assert not rule.matches("file_system", "write")


def test_policy_engine_allows_matching_rule(basic_policy):
    """Test policy engine allows request matching allow rule."""
    engine = PolicyEngine(basic_policy)

    request = ToolCallRequest(tool="file_system", action="read", resource="/test/path")

    decision = engine.evaluate(request, RiskTier.LOW, {})
    assert decision.outcome == DecisionOutcome.ALLOW


def test_policy_engine_denies_matching_deny_rule(basic_policy):
    """Test policy engine denies request matching deny rule."""
    engine = PolicyEngine(basic_policy)

    request = ToolCallRequest(tool="file_system", action="delete", resource="/test/path")

    decision = engine.evaluate(request, RiskTier.HIGH, {})
    assert decision.outcome == DecisionOutcome.DENY


def test_policy_engine_default_deny(basic_policy):
    """Test policy engine uses default deny."""
    engine = PolicyEngine(basic_policy)

    request = ToolCallRequest(tool="file_system", action="write", resource="/test/path")

    decision = engine.evaluate(request, RiskTier.MEDIUM, {})
    assert decision.outcome == DecisionOutcome.DENY


def test_time_constraint_allows_within_window():
    """Test time constraint allows within time window."""
    constraint = TimeConstraint(
        start_time="09:00", end_time="17:00", days=["mon", "tue", "wed", "thu", "fri"]
    )

    assert constraint.is_allowed(time_type(10, 0), "mon")
    assert constraint.is_allowed(time_type(16, 30), "wed")


def test_time_constraint_denies_outside_window():
    """Test time constraint denies outside time window."""
    constraint = TimeConstraint(
        start_time="09:00", end_time="17:00", days=["mon", "tue", "wed", "thu", "fri"]
    )

    assert not constraint.is_allowed(time_type(8, 0), "mon")
    assert not constraint.is_allowed(time_type(18, 0), "wed")
    assert not constraint.is_allowed(time_type(10, 0), "sat")


def test_rate_limiter():
    """Test rate limiter enforces limits."""
    from provsafe.policy.engine import RateLimiter
    from datetime import datetime

    limiter = RateLimiter()
    constraint = RateLimitConstraint(max_calls=3, window_seconds=60)

    now = datetime.now()

    # First 3 calls should be allowed
    for i in range(3):
        is_allowed, count = limiter.check_limit("test_key", constraint, now)
        assert is_allowed
        limiter.record_call("test_key", now)

    # 4th call should be denied
    is_allowed, count = limiter.check_limit("test_key", constraint, now)
    assert not is_allowed
    assert count == 3

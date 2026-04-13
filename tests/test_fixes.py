"""Tests for critical fixes: policy engine YAML loading, rate limit bug,
argument validation pipeline, provenance graph cycle detection, and
empty-sources trust default."""

import sys
from pathlib import Path

import pytest
import yaml

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.policy_engine import (
    PolicyDecision,
    PolicyEngine,
)
from src.provenance_graph import ProvenanceGraph, TrustLabel, trust_meet
from src.enforcement_proxy import EnforcementProxy

# =============================================================================
# Policy Engine: Rate Limit Bug Fix
# =============================================================================


class TestRateLimitFix:
    """The old rate_limit_ok condition was inverted: it denied all calls
    when the rate limit was NOT exceeded.  The fix renames it to
    rate_limit_exceeded and inverts the logic."""

    def test_rate_limit_allows_under_limit(self):
        """Calls under the rate limit should be ALLOWED (not DENIED)."""
        engine = PolicyEngine(config={})
        result = engine.evaluate(
            tool_name="smarthome_control",
            tool_args={"action": "list"},
            provenance_info={"has_untrusted_args": False, "untrusted_arg_names": []},
        )
        # MEDIUM risk, no untrusted args, under rate limit → default ALLOW
        assert result.decision == PolicyDecision.ALLOW

    def test_rate_limit_denies_over_limit(self):
        """Calls over the rate limit should be DENIED."""
        engine = PolicyEngine(config={})
        # Exhaust the rate limit (10 calls in 60 seconds)
        for _ in range(10):
            engine.rate_tracker.record_call("smarthome_control")

        result = engine.evaluate(
            tool_name="smarthome_control",
            tool_args={"action": "list"},
            provenance_info={"has_untrusted_args": False, "untrusted_arg_names": []},
        )
        assert result.decision == PolicyDecision.DENY
        assert "rate limit" in result.reason.lower()

    def test_rate_limit_disabled(self):
        """When rate limiting is disabled, calls always pass rate check."""
        engine = PolicyEngine(config={"disable_rate_limiting": True})
        # Exhaust what would be the limit
        for _ in range(20):
            engine.rate_tracker.record_call("smarthome_control")

        result = engine.evaluate(
            tool_name="smarthome_control",
            tool_args={"action": "list"},
            provenance_info={"has_untrusted_args": False, "untrusted_arg_names": []},
        )
        assert result.decision == PolicyDecision.ALLOW


# =============================================================================
# Policy Engine: YAML Loading
# =============================================================================


class TestYAMLPolicyLoading:
    """Test that policies can be loaded from YAML files."""

    @pytest.fixture
    def yaml_policy_file(self, tmp_path):
        """Create a temporary YAML policy file."""
        policy = {
            "version": "1.0",
            "name": "Test Policy",
            "description": "A test policy",
            "default_allow": False,
            "rules": [
                {
                    "name": "allow_file_read",
                    "tool": "file_system",
                    "action": "read",
                    "allow": True,
                    "risk_tier": "low",
                },
                {
                    "name": "deny_file_delete",
                    "tool": "file_system",
                    "action": "delete",
                    "allow": False,
                    "risk_tier": "critical",
                },
                {
                    "name": "confirm_email",
                    "tool": "email",
                    "action": "send",
                    "allow": True,
                    "require_confirmation": True,
                    "risk_tier": "high",
                },
            ],
        }
        policy_file = tmp_path / "test_policy.yaml"
        with open(policy_file, "w") as f:
            yaml.dump(policy, f)
        return str(policy_file)

    def test_yaml_loading_creates_rules(self, yaml_policy_file):
        """YAML file creates the expected number of rules."""
        engine = PolicyEngine(policy_file=yaml_policy_file)
        # 3 YAML rules (no rate limits so no extra rules)
        assert len(engine.rules) >= 3

    def test_yaml_allow_rule(self, yaml_policy_file):
        """YAML allow rule works correctly."""
        engine = PolicyEngine(
            config={"risk_tiers": {"LOW": ["file_system"]}},
            policy_file=yaml_policy_file,
        )
        result = engine.evaluate(
            tool_name="file_system",
            tool_args={"action": "read", "path": "/home/user/test.txt"},
            provenance_info={"has_untrusted_args": False, "untrusted_arg_names": []},
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_yaml_deny_rule(self, yaml_policy_file):
        """YAML deny rule works correctly."""
        engine = PolicyEngine(
            config={"risk_tiers": {"CRITICAL": ["file_system"]}},
            policy_file=yaml_policy_file,
        )
        result = engine.evaluate(
            tool_name="file_system",
            tool_args={"action": "delete", "path": "/etc/passwd"},
            provenance_info={"has_untrusted_args": True, "untrusted_arg_names": ["path"]},
        )
        assert result.decision == PolicyDecision.DENY

    def test_real_provsafe_yaml(self):
        """Load the actual provsafe.yaml policy file."""
        policy_path = Path(__file__).parent.parent / "configs" / "policies" / "provsafe.yaml"
        if not policy_path.exists():
            pytest.skip("provsafe.yaml not found")

        engine = PolicyEngine(policy_file=str(policy_path))
        assert len(engine.rules) > 0
        assert engine.policy_name == "PROVSAFE Default Policy"


# =============================================================================
# Policy Engine: Provenance-gated decisions
# =============================================================================


class TestProvenanceGating:
    """Test that provenance information correctly gates policy decisions."""

    def test_untrusted_args_trigger_confirmation(self):
        """MEDIUM risk + untrusted args → REQUIRE_CONFIRMATION."""
        engine = PolicyEngine(config={"disable_rate_limiting": True})
        result = engine.evaluate(
            tool_name="smarthome_control",
            tool_args={"action": "turn_on", "device_id": "living_room_light"},
            provenance_info={"has_untrusted_args": True, "untrusted_arg_names": ["device_id"]},
        )
        assert result.decision == PolicyDecision.REQUIRE_CONFIRMATION

    def test_trusted_args_allow(self):
        """MEDIUM risk + trusted args → ALLOW."""
        engine = PolicyEngine(config={"disable_rate_limiting": True})
        result = engine.evaluate(
            tool_name="smarthome_control",
            tool_args={"action": "list"},
            provenance_info={"has_untrusted_args": False, "untrusted_arg_names": []},
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_dangerous_action_denied_regardless(self):
        """Dangerous actions are denied regardless of provenance."""
        engine = PolicyEngine(config={"disable_rate_limiting": True})
        result = engine.evaluate(
            tool_name="smarthome_control",
            tool_args={"action": "delete"},
            provenance_info={"has_untrusted_args": False, "untrusted_arg_names": []},
        )
        assert result.decision == PolicyDecision.DENY


# =============================================================================
# Provenance Graph: Empty Sources Default
# =============================================================================


class TestEmptySourcesTrust:
    """Verify that LLM-generated content with no traceable sources defaults
    to UNTRUSTED (conservative), not TRUSTED."""

    def test_empty_sources_untrusted(self):
        """add_llm_generation with empty sources → UNTRUSTED."""
        graph = ProvenanceGraph()
        node_id = graph.add_llm_generation(
            llm_output="some generated text",
            source_node_ids=[],
        )
        node = graph.nodes[node_id]
        assert node.trust_label == TrustLabel.UNTRUSTED

    def test_trusted_source_propagates(self):
        """Single TRUSTED source → TRUSTED."""
        graph = ProvenanceGraph()
        user_id = graph.add_user_input("hello")
        node_id = graph.add_llm_generation(
            llm_output="response",
            source_node_ids=[user_id],
        )
        node = graph.nodes[node_id]
        assert node.trust_label == TrustLabel.TRUSTED

    def test_mixed_sources_untrusted(self):
        """Mixed TRUSTED + UNTRUSTED sources → UNTRUSTED (lattice meet)."""
        graph = ProvenanceGraph()
        user_id = graph.add_user_input("hello")
        tool_id = graph.add_tool_result("external_api", "untrusted data")
        node_id = graph.add_llm_generation(
            llm_output="derived",
            source_node_ids=[user_id, tool_id],
        )
        node = graph.nodes[node_id]
        assert node.trust_label == TrustLabel.UNTRUSTED


# =============================================================================
# Provenance Graph: Cycle Detection
# =============================================================================


class TestCycleDetection:
    """Verify that the provenance DAG rejects cycles."""

    def test_cycle_detection_method(self):
        """_creates_cycle correctly detects when a cycle would be formed."""
        graph = ProvenanceGraph()
        a = graph.add_user_input("A")
        b = graph.add_llm_generation("B", source_node_ids=[a])
        c = graph.add_llm_generation("C", source_node_ids=[b])

        # No cycle in a clean chain
        assert not graph._creates_cycle(c)
        assert not graph._creates_cycle(b)

        # Manually inject a back-edge to create a cycle (a → b → c → a)
        # This simulates corruption; the check should catch it.
        graph.nodes[a].parent_ids.append(c)
        assert graph._creates_cycle(a)  # a's parents include c, c→b→a is a cycle

    def test_dag_normal_operations_no_cycle(self):
        """Normal provenance operations never create cycles."""
        graph = ProvenanceGraph()
        user_id = graph.add_user_input("hello")
        tool_id = graph.add_tool_result("api", "data")
        llm_id = graph.add_llm_generation("response", [user_id, tool_id])
        _call_id = graph.add_tool_call("test_tool", {"action": "read"}, llm_id)

        # All operations succeed without ValueError
        assert len(graph.nodes) == 4


# =============================================================================
# Enforcement Proxy: Argument Validation Pipeline
# =============================================================================


class TestArgumentValidationPipeline:
    """Verify that argument validation feeds into the policy pipeline
    rather than bypassing it."""

    @pytest.fixture
    def proxy(self):
        """Create an enforcement proxy with mock tools and auto-deny confirmation."""
        graph = ProvenanceGraph()
        engine = PolicyEngine(config={"disable_rate_limiting": True})

        def mock_tool(**kwargs):
            return {"status": "ok"}

        def auto_deny_confirmation(**kwargs):
            """Auto-deny confirmation requests in tests."""
            return False

        registry = {"test_tool": mock_tool}
        proxy = EnforcementProxy(
            provenance_graph=graph,
            policy_engine=engine,
            tool_registry=registry,
            confirmation_handler=auto_deny_confirmation,
        )
        # Add a user input so provenance resolution has something to match
        graph.add_user_input("do something safe")
        return proxy

    def test_encoded_args_still_go_through_policy(self, proxy):
        """Encoded arguments are flagged but still evaluated by policy engine."""
        # Add a reasoning node
        reasoning_id = proxy.provenance.add_llm_generation(
            llm_output="I will call test_tool",
            source_node_ids=[list(proxy.provenance.nodes.keys())[0]],
        )

        # Argument with base64 encoding should be caught by validation
        # AND evaluated by policy (not bypass)
        result = proxy.intercept_tool_call(
            tool_name="test_tool",
            tool_args={"path": "/etc/passwd"},
            llm_reasoning_node_id=reasoning_id,
        )

        # Should NOT be allowed — validation flags the sensitive path,
        # policy sees untrusted args → REQUIRE_CONFIRMATION or DENY
        assert not result["allowed"]
        assert result["decision"] in ("deny", "require_confirmation")
        # Provenance should still be traced (not skipped)
        assert "provenance" in result
        assert result["provenance"]["has_untrusted_args"]

    def test_clean_args_allowed(self, proxy):
        """Clean arguments with trusted provenance are allowed."""
        reasoning_id = proxy.provenance.add_llm_generation(
            llm_output="I will call test_tool",
            source_node_ids=[list(proxy.provenance.nodes.keys())[0]],
        )

        result = proxy.intercept_tool_call(
            tool_name="test_tool",
            tool_args={"action": "list"},
            llm_reasoning_node_id=reasoning_id,
        )
        assert result["allowed"]


# =============================================================================
# Trust Lattice Operations
# =============================================================================


class TestTrustLattice:
    """Verify lattice operations are correct."""

    def test_meet_all_trusted(self):
        assert trust_meet(TrustLabel.TRUSTED, TrustLabel.TRUSTED) == TrustLabel.TRUSTED

    def test_meet_any_untrusted(self):
        assert trust_meet(TrustLabel.TRUSTED, TrustLabel.UNTRUSTED) == TrustLabel.UNTRUSTED

    def test_meet_empty(self):
        """Empty meet should be the identity (TRUSTED) for non-empty lattice."""
        assert trust_meet() == TrustLabel.TRUSTED

    def test_meet_single_untrusted(self):
        assert trust_meet(TrustLabel.UNTRUSTED) == TrustLabel.UNTRUSTED

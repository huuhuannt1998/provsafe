#!/usr/bin/env python3
"""
PROVSAFE Policy Engine Implementation

Evaluates declarative policies against tool calls considering:
- Tool risk tiers (LOW, MEDIUM, HIGH, CRITICAL)
- Provenance constraints (argument origins)
- Scope restrictions (path prefixes, resource boundaries)
- Temporal rules (time-of-day)
- Rate limits
- Evidence requirements

Policies can be loaded from YAML files (declarative) or fall back to
built-in defaults when no YAML is provided.
"""

import re
import time
import logging
from dataclasses import dataclass
from datetime import datetime, time as dt_time
from enum import Enum
from typing import Any, Dict, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class PolicyDecision(Enum):
    """Policy evaluation decisions."""
    ALLOW = "allow"              # Execute without confirmation
    DENY = "deny"                # Block execution
    REQUIRE_CONFIRMATION = "require_confirmation"  # Ask user


class RiskTier(Enum):
    """Tool risk tiers."""
    LOW = "low"          # Read-only, minimal impact
    MEDIUM = "medium"    # Write operations, moderate impact
    HIGH = "high"        # Destructive operations, high impact
    CRITICAL = "critical"  # System-level, irreversible


@dataclass
class PolicyRule:
    """A single policy rule."""
    name: str
    priority: int  # Lower = higher priority
    conditions: List[Dict[str, Any]]
    decision: PolicyDecision
    reason: str

    def matches(self, context: Dict[str, Any]) -> bool:
        """Check if all conditions match the context."""
        for condition in self.conditions:
            if not self._evaluate_condition(condition, context):
                return False
        return True

    def _evaluate_condition(self, condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate a single condition."""
        cond_type = condition.get("type")

        if cond_type == "tool_name":
            return context.get("tool_name") == condition.get("value")

        elif cond_type == "action_name":
            # Match the 'action' argument of the tool call
            tool_args = context.get("tool_args", {})
            return tool_args.get("action", "") == condition.get("value")

        elif cond_type == "tool_pattern":
            pattern = condition.get("pattern")
            return bool(re.match(pattern, context.get("tool_name", "")))

        elif cond_type == "risk_tier":
            return context.get("risk_tier") == condition.get("value")

        elif cond_type == "risk_tier_min":
            # Matches if risk tier is >= the specified minimum
            tier_order = {RiskTier.LOW: 0, RiskTier.MEDIUM: 1, RiskTier.HIGH: 2, RiskTier.CRITICAL: 3}
            ctx_tier = context.get("risk_tier", RiskTier.MEDIUM)
            min_tier = condition.get("value", RiskTier.MEDIUM)
            return tier_order.get(ctx_tier, 1) >= tier_order.get(min_tier, 1)

        elif cond_type == "has_untrusted_args":
            return context.get("has_untrusted_args") == condition.get("value")

        elif cond_type == "scope_allowed":
            # Check if path/resource is in allowed scope
            resource = context.get("resource_path")
            allowed_patterns = condition.get("patterns", [])
            denied_patterns = condition.get("deny_patterns", [])

            # Check deny patterns first
            for pattern in denied_patterns:
                if self._match_scope_pattern(pattern, resource):
                    return False

            # Then check allow patterns
            if not allowed_patterns:
                return True
            return any(self._match_scope_pattern(p, resource) for p in allowed_patterns)

        elif cond_type == "time_allowed":
            current_time = datetime.now().time()
            start_time = dt_time.fromisoformat(condition.get("start", "00:00:00"))
            end_time = dt_time.fromisoformat(condition.get("end", "23:59:59"))
            return start_time <= current_time <= end_time

        elif cond_type == "rate_limit_exceeded":
            # Returns True when the rate limit IS exceeded (too many calls)
            tool_name = context.get("tool_name")
            rate_tracker = context.get("rate_tracker")
            max_calls = condition.get("max_calls")
            window_seconds = condition.get("window_seconds")

            if rate_tracker and tool_name:
                # check_rate_limit returns True if under limit (allowed)
                return not rate_tracker.check_rate_limit(tool_name, max_calls, window_seconds)
            return False

        elif cond_type == "dangerous_action":
            # Check if action is inherently dangerous
            tool_args = context.get("tool_args", {})
            action = tool_args.get("action", "")

            # Dangerous actions that should always be carefully controlled
            if action in ["delete", "format", "wipe"]:
                return True

            # Unlock without specific authorization
            if action == "unlock":
                return True

            # Extreme temperature settings
            if action == "set_temperature":
                try:
                    temp = float(tool_args.get("temperature", 70))
                except (ValueError, TypeError):
                    temp = 70
                if temp > 85 or temp < 55:
                    return True

            # Write to sensitive locations
            if action == "write":
                path = tool_args.get("path", "")
                if any(sensitive in path for sensitive in ["/etc", "/sys", "/root", ".ssh", "authorized_keys"]):
                    return True

            return False

        return True

    def _match_scope_pattern(self, pattern: str, path: str) -> bool:
        """Match path against scope pattern with wildcard support."""
        if not path:
            return False

        # Convert glob pattern to regex
        # /tmp/** -> /tmp/.*
        # /home/user/* -> /home/user/[^/]+
        regex_pattern = pattern.replace("**", ".*").replace("*", "[^/]+")
        regex_pattern = "^" + regex_pattern + "$"

        return bool(re.match(regex_pattern, path))


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation."""
    decision: PolicyDecision
    matched_rule: Optional[PolicyRule]
    reason: str
    requires_confirmation: bool
    metadata: Dict[str, Any]


class RateTracker:
    """Tracks tool call rates for rate limiting."""

    def __init__(self):
        self.call_history: Dict[str, List[float]] = defaultdict(list)

    def record_call(self, tool_name: str):
        """Record a tool call."""
        self.call_history[tool_name].append(time.time())

    def check_rate_limit(self, tool_name: str, max_calls: int, window_seconds: int) -> bool:
        """Check if rate limit would be exceeded. Returns True if under limit (allowed)."""
        current_time = time.time()
        cutoff_time = current_time - window_seconds

        # Remove old calls outside window
        self.call_history[tool_name] = [
            t for t in self.call_history[tool_name]
            if t > cutoff_time
        ]

        # Check if adding one more call would exceed limit
        return len(self.call_history[tool_name]) < max_calls

    def get_call_count(self, tool_name: str, window_seconds: int) -> int:
        """Get number of calls in the window."""
        current_time = time.time()
        cutoff_time = current_time - window_seconds

        return sum(1 for t in self.call_history[tool_name] if t > cutoff_time)


class PolicyEngine:
    """
    Evaluates declarative policies against tool calls with provenance context.

    Supports loading rules from YAML policy files (configs/policies/*.yaml)
    with first-match semantics (rules evaluated in priority order).
    Falls back to built-in defaults when no YAML is provided.

    Policy evaluation order:
    1. Check explicit DENY rules (highest priority)
    2. Check rate limits
    3. Check scope constraints
    4. Check provenance constraints
    5. Check risk tier rules
    6. Default to ALLOW for low-risk, REQUIRE_CONFIRMATION for high-risk
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None, policy_file: Optional[str] = None):
        self.config = config or {}
        self.rules: List[PolicyRule] = []
        self.rate_tracker = RateTracker()

        if policy_file:
            self._load_rules_from_yaml(policy_file)
        else:
            self._load_default_rules()

    def _load_rules_from_yaml(self, policy_file: str):
        """Load policy rules from a YAML file.

        YAML rule format:
            rules:
              - name: "rule_name"
                tool: "tool_name"         # optional
                action: "action_name"     # optional
                resource_pattern: "^/..."  # optional regex
                allow: true/false
                require_confirmation: false  # optional
                risk_tier: "low|medium|high|critical"
                rate_limit:                 # optional
                  max_calls: 10
                  window_seconds: 3600
        """
        import yaml

        with open(policy_file, 'r') as f:
            policy_data = yaml.safe_load(f)

        self.policy_name = policy_data.get("name", "unnamed")
        self.default_allow = policy_data.get("default_allow", False)

        # Load global rate limit
        global_rl = policy_data.get("global_rate_limit")
        if global_rl and not self.config.get("disable_rate_limiting", False):
            self.rules.append(PolicyRule(
                name="global_rate_limit",
                priority=0,
                conditions=[
                    {
                        "type": "rate_limit_exceeded",
                        "max_calls": global_rl["max_calls"],
                        "window_seconds": global_rl["window_seconds"],
                    },
                ],
                decision=PolicyDecision.DENY,
                reason="Global rate limit exceeded",
            ))

        # Load rules
        yaml_rules = policy_data.get("rules", [])
        for idx, rule_def in enumerate(yaml_rules):
            conditions = []

            # Tool name condition
            if "tool" in rule_def:
                conditions.append({"type": "tool_name", "value": rule_def["tool"]})

            # Action condition (e.g. action: "read" matches tool calls where args["action"] == "read")
            if "action" in rule_def:
                conditions.append({"type": "action_name", "value": rule_def["action"]})

            # Risk tier condition
            if "risk_tier" in rule_def:
                tier_str = rule_def["risk_tier"].upper()
                conditions.append({"type": "risk_tier", "value": RiskTier[tier_str]})

            # Resource pattern condition (scope check)
            if "resource_pattern" in rule_def:
                conditions.append({
                    "type": "scope_allowed",
                    "patterns": [rule_def["resource_pattern"]],
                    "deny_patterns": [],
                })

            # Determine decision
            if not rule_def.get("allow", True):
                decision = PolicyDecision.DENY
            elif rule_def.get("require_confirmation", False):
                decision = PolicyDecision.REQUIRE_CONFIRMATION
            else:
                decision = PolicyDecision.ALLOW

            # Per-rule rate limit
            if "rate_limit" in rule_def and not self.config.get("disable_rate_limiting", False):
                rl = rule_def["rate_limit"]
                conditions.append({
                    "type": "rate_limit_exceeded",
                    "max_calls": rl["max_calls"],
                    "window_seconds": rl["window_seconds"],
                })
                # If rate limit exceeded, override decision to DENY
                # Create a separate rate-limit deny rule with higher priority
                self.rules.append(PolicyRule(
                    name=f"{rule_def['name']}_rate_limit",
                    priority=idx + 1,
                    conditions=[
                        {"type": "tool_name", "value": rule_def.get("tool", "*")},
                        {
                            "type": "rate_limit_exceeded",
                            "max_calls": rl["max_calls"],
                            "window_seconds": rl["window_seconds"],
                        },
                    ],
                    decision=PolicyDecision.DENY,
                    reason=f"Rate limit exceeded for {rule_def['name']}",
                ))

            self.rules.append(PolicyRule(
                name=rule_def["name"],
                priority=100 + idx,  # YAML rules after rate-limit rules
                conditions=conditions,
                decision=decision,
                reason=rule_def.get("description", rule_def["name"]),
            ))

        logger.info(
            "Loaded %d rules from %s (policy: %s)",
            len(self.rules), policy_file, self.policy_name,
        )

    def _load_default_rules(self):
        """Load built-in default policy rules."""
        # Rule 1: DENY critical operations with untrusted args
        self.rules.append(PolicyRule(
            name="deny_critical_untrusted",
            priority=1,
            conditions=[
                {"type": "risk_tier", "value": RiskTier.CRITICAL},
                {"type": "has_untrusted_args", "value": True},
            ],
            decision=PolicyDecision.DENY,
            reason="CRITICAL operation with untrusted arguments blocked",
        ))

        # Rule 2: DENY HIGH-risk operations with untrusted args outside allowed scope
        self.rules.append(PolicyRule(
            name="deny_high_untrusted_outscope",
            priority=2,
            conditions=[
                {"type": "risk_tier", "value": RiskTier.HIGH},
                {"type": "has_untrusted_args", "value": True},
                {"type": "scope_allowed", "patterns": [], "deny_patterns": []},
            ],
            decision=PolicyDecision.DENY,
            reason="HIGH-risk operation with untrusted arguments outside allowed scope",
        ))

        # Rule 3: REQUIRE_CONFIRMATION for HIGH-risk with untrusted args in allowed scope
        self.rules.append(PolicyRule(
            name="confirm_high_untrusted",
            priority=3,
            conditions=[
                {"type": "risk_tier", "value": RiskTier.HIGH},
                {"type": "has_untrusted_args", "value": True},
            ],
            decision=PolicyDecision.REQUIRE_CONFIRMATION,
            reason="HIGH-risk operation with untrusted arguments requires confirmation",
        ))

        # Rule 4: REQUIRE_CONFIRMATION for MEDIUM-risk with untrusted args
        self.rules.append(PolicyRule(
            name="confirm_medium_untrusted",
            priority=4,
            conditions=[
                {"type": "risk_tier", "value": RiskTier.MEDIUM},
                {"type": "has_untrusted_args", "value": True},
            ],
            decision=PolicyDecision.REQUIRE_CONFIRMATION,
            reason="MEDIUM-risk operation with untrusted arguments requires confirmation",
        ))

        # Rule 5: DENY if rate limit exceeded
        if not self.config.get("disable_rate_limiting", False):
            self.rules.append(PolicyRule(
                name="deny_rate_limit",
                priority=5,
                conditions=[
                    {"type": "rate_limit_exceeded", "max_calls": 10, "window_seconds": 60},
                ],
                decision=PolicyDecision.DENY,
                reason="Rate limit exceeded",
            ))

        # Rule 6: DENY dangerous actions regardless of provenance
        self.rules.append(PolicyRule(
            name="deny_dangerous_actions",
            priority=6,
            conditions=[
                {"type": "dangerous_action", "value": True},
            ],
            decision=PolicyDecision.DENY,
            reason="Inherently dangerous action blocked",
        ))

        # Rule 7: ALLOW LOW-risk operations
        self.rules.append(PolicyRule(
            name="allow_low_risk",
            priority=10,
            conditions=[
                {"type": "risk_tier", "value": RiskTier.LOW},
            ],
            decision=PolicyDecision.ALLOW,
            reason="LOW-risk operation allowed",
        ))

    def evaluate(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        provenance_info: Dict[str, Any]
    ) -> PolicyEvaluationResult:
        """
        Evaluate policy for a tool call.

        Args:
            tool_name: Name of the tool being called
            tool_args: Arguments passed to the tool
            provenance_info: Result from ProvenanceGraph.trace_argument_provenance()

        Returns:
            PolicyEvaluationResult with decision and reason
        """
        start_time = time.time()

        # Determine risk tier
        risk_tier = self._get_risk_tier(tool_name)

        # Extract resource path if applicable
        resource_path = self._extract_resource_path(tool_name, tool_args)

        # Build evaluation context
        context = {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "risk_tier": risk_tier,
            "has_untrusted_args": provenance_info.get("has_untrusted_args", False),
            "untrusted_arg_names": provenance_info.get("untrusted_arg_names", []),
            "resource_path": resource_path,
            "rate_tracker": self.rate_tracker,
        }

        # Evaluate rules in priority order
        for rule in sorted(self.rules, key=lambda r: r.priority):
            if rule.matches(context):
                # Record call for rate tracking
                self.rate_tracker.record_call(tool_name)

                latency_ms = (time.time() - start_time) * 1000

                return PolicyEvaluationResult(
                    decision=rule.decision,
                    matched_rule=rule,
                    reason=rule.reason,
                    requires_confirmation=(rule.decision == PolicyDecision.REQUIRE_CONFIRMATION),
                    metadata={
                        "risk_tier": risk_tier.value,
                        "has_untrusted_args": context["has_untrusted_args"],
                        "untrusted_args": context["untrusted_arg_names"],
                        "resource_path": resource_path,
                        "latency_ms": latency_ms,
                    }
                )

        # Default: respect policy's default_allow; deny-by-default when false (loaded from YAML).
        # For built-in rules, HIGH/CRITICAL always require confirmation.
        if not getattr(self, "default_allow", True):
            default_decision = PolicyDecision.DENY
        elif risk_tier in [RiskTier.HIGH, RiskTier.CRITICAL]:
            default_decision = PolicyDecision.REQUIRE_CONFIRMATION
        else:
            default_decision = PolicyDecision.ALLOW

        latency_ms = (time.time() - start_time) * 1000

        return PolicyEvaluationResult(
            decision=default_decision,
            matched_rule=None,
            reason=f"Default policy for {risk_tier.value} risk tier",
            requires_confirmation=(default_decision == PolicyDecision.REQUIRE_CONFIRMATION),
            metadata={
                "risk_tier": risk_tier.value,
                "has_untrusted_args": context["has_untrusted_args"],
                "latency_ms": latency_ms,
            }
        )

    def _get_risk_tier(self, tool_name: str) -> RiskTier:
        """Determine risk tier for a tool."""
        risk_tiers = self.config.get("risk_tiers", {})

        for tier_name, tool_list in risk_tiers.items():
            if tool_name in tool_list:
                return RiskTier[tier_name]

        # Default to MEDIUM if not specified
        return RiskTier.MEDIUM

    def _extract_resource_path(self, tool_name: str, tool_args: Dict[str, Any]) -> Optional[str]:
        """Extract resource path from tool arguments."""
        # Common path argument names
        path_keys = ["path", "file_path", "filepath", "directory", "dir", "target"]

        for key in path_keys:
            if key in tool_args:
                return tool_args[key]

        return None

    def get_scope_constraints(self, tool_name: str) -> Dict[str, List[str]]:
        """Get scope constraints for a tool."""
        scope_config = self.config.get("scope_constraints", {})
        return scope_config.get(tool_name, {"allowed": [], "denied": []})

    def get_rate_limit(self, tool_name: str) -> Optional[Dict[str, int]]:
        """Get rate limit configuration for a tool."""
        rate_limits = self.config.get("rate_limits", {})
        return rate_limits.get(tool_name)

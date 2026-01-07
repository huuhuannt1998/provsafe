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
"""

import re
import time
from dataclasses import dataclass
from datetime import datetime, time as dt_time
from enum import Enum
from typing import Any, Dict, List, Optional
from collections import defaultdict


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
        
        elif cond_type == "tool_pattern":
            pattern = condition.get("pattern")
            return re.match(pattern, context.get("tool_name", ""))
        
        elif cond_type == "risk_tier":
            return context.get("risk_tier") == condition.get("value")
        
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
        
        elif cond_type == "rate_limit_ok":
            tool_name = context.get("tool_name")
            rate_tracker = context.get("rate_tracker")
            max_calls = condition.get("max_calls")
            window_seconds = condition.get("window_seconds")
            
            if rate_tracker and tool_name:
                return rate_tracker.check_rate_limit(tool_name, max_calls, window_seconds)
            return True
        
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
        """Check if rate limit would be exceeded."""
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
    
    Policy evaluation order:
    1. Check explicit DENY rules (highest priority)
    2. Check rate limits
    3. Check scope constraints
    4. Check provenance constraints
    5. Check risk tier rules
    6. Default to ALLOW for low-risk, REQUIRE_CONFIRMATION for high-risk
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules: List[PolicyRule] = []
        self.rate_tracker = RateTracker()
        self._load_rules()
    
    def _load_rules(self):
        """Load policy rules from configuration."""
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
                {"type": "scope_allowed", "patterns": [], "deny_patterns": []},  # Will check per-tool
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
        
        # Rule 5: DENY if rate limit exceeded (skip if disabled in config)
        if not self.config.get("disable_rate_limiting", False):
            self.rules.append(PolicyRule(
                name="deny_rate_limit",
                priority=5,
                conditions=[
                    {"type": "rate_limit_ok", "max_calls": 10, "window_seconds": 60},
                ],
                decision=PolicyDecision.DENY,
                reason="Rate limit exceeded",
            ))
        
        # Rule 6: ALLOW LOW-risk operations
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
        
        # Default: HIGH/CRITICAL risk requires confirmation, others allow
        default_decision = (
            PolicyDecision.REQUIRE_CONFIRMATION
            if risk_tier in [RiskTier.HIGH, RiskTier.CRITICAL]
            else PolicyDecision.ALLOW
        )
        
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

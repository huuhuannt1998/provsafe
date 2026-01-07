"""Policy evaluation engine."""

from typing import Dict, Any, Optional
from datetime import datetime
from collections import defaultdict

from .language import CapabilityPolicy, PolicyRule, RateLimitConstraint
from ..proxy.schema import (
    ToolCallRequest,
    PolicyDecision,
    DecisionOutcome,
    ReasonCode,
    RiskTier,
)


class RateLimiter:
    """Rate limit tracker."""
    
    def __init__(self):
        self._calls: Dict[str, list] = defaultdict(list)
    
    def check_limit(
        self,
        key: str,
        constraint: RateLimitConstraint,
        current_time: datetime
    ) -> tuple[bool, int]:
        """
        Check if rate limit is exceeded.
        
        Returns:
            (is_allowed, current_count)
        """
        # Clean old entries
        cutoff = current_time.timestamp() - constraint.window_seconds
        self._calls[key] = [t for t in self._calls[key] if t > cutoff]
        
        # Check limit
        current_count = len(self._calls[key])
        is_allowed = current_count < constraint.max_calls
        
        return is_allowed, current_count
    
    def record_call(self, key: str, timestamp: datetime):
        """Record a call for rate limiting."""
        self._calls[key].append(timestamp.timestamp())


class PolicyEngine:
    """
    Policy evaluation engine.
    
    Evaluates tool call requests against capability policies,
    applying constraints and evidence requirements.
    """
    
    def __init__(self, policy: CapabilityPolicy):
        self.policy = policy
        self.rate_limiter = RateLimiter()
    
    def evaluate(
        self,
        request: ToolCallRequest,
        risk_tier: RiskTier,
        user_context: Dict[str, Any]
    ) -> PolicyDecision:
        """
        Evaluate a tool call request against policy.
        
        Args:
            request: Tool call request
            risk_tier: Risk tier from schema
            user_context: User/session context
            
        Returns:
            PolicyDecision with outcome and reason codes
        """
        current_time = datetime.now()
        
        # Find matching rule
        matching_rule = self.policy.find_matching_rule(
            request.tool,
            request.action,
            request.resource
        )
        
        # No matching rule
        if not matching_rule:
            if self.policy.default_allow:
                return PolicyDecision(
                    outcome=DecisionOutcome.ALLOW,
                    reason_code=ReasonCode.ALLOWED_BY_POLICY,
                    explanation="No matching rule, default allow",
                    risk_tier=risk_tier
                )
            else:
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    reason_code=ReasonCode.DENIED_NO_RULE,
                    explanation="No matching rule, default deny",
                    risk_tier=risk_tier
                )
        
        # Rule explicitly denies
        if not matching_rule.allow:
            return PolicyDecision(
                outcome=DecisionOutcome.DENY,
                reason_code=ReasonCode.DENIED_BLACKLIST,
                explanation=f"Denied by rule: {matching_rule.name}",
                matched_rule=matching_rule.name,
                risk_tier=risk_tier
            )
        
        # Check time constraints
        if matching_rule.time_constraints:
            current_day = current_time.strftime("%a").lower()
            time_allowed = any(
                tc.is_allowed(current_time.time(), current_day)
                for tc in matching_rule.time_constraints
            )
            if not time_allowed:
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    reason_code=ReasonCode.DENIED_TIME_CONSTRAINT,
                    explanation="Request outside allowed time window",
                    matched_rule=matching_rule.name,
                    risk_tier=risk_tier
                )
        
        # Check rate limits
        rate_limit = matching_rule.rate_limit or self.policy.global_rate_limit
        if rate_limit:
            user_id = user_context.get("user_id", "anonymous")
            scope_key = f"{user_id}:{request.tool}:{request.action}"
            
            is_allowed, current_count = self.rate_limiter.check_limit(
                scope_key, rate_limit, current_time
            )
            
            if not is_allowed:
                return PolicyDecision(
                    outcome=DecisionOutcome.DENY,
                    reason_code=ReasonCode.DENIED_RATE_LIMIT,
                    explanation=f"Rate limit exceeded: {current_count}/{rate_limit.max_calls}",
                    matched_rule=matching_rule.name,
                    risk_tier=risk_tier,
                    metadata={"current_count": current_count, "max_calls": rate_limit.max_calls}
                )
            
            # Record the call
            self.rate_limiter.record_call(scope_key, current_time)
        
        # Check evidence requirements
        required_evidence = []
        if matching_rule.evidence_requirements:
            ev_req = matching_rule.evidence_requirements
            
            # Check if we have sufficient provenance
            provenance_data = request.context.get("provenance", {})
            trusted_sources = provenance_data.get("trusted_sources", 0)
            
            if ev_req.min_trusted_sources > trusted_sources:
                required_evidence.append(
                    f"Requires {ev_req.min_trusted_sources} trusted sources, have {trusted_sources}"
                )
            
            if ev_req.require_user_confirmation or risk_tier == RiskTier.HIGH:
                return PolicyDecision(
                    outcome=DecisionOutcome.CONFIRM,
                    reason_code=ReasonCode.CONFIRM_HIGH_RISK,
                    explanation=f"High-risk action requires confirmation: {matching_rule.name}",
                    matched_rule=matching_rule.name,
                    risk_tier=risk_tier,
                    required_evidence=required_evidence
                )
        
        # Allow with constraints
        outcome = DecisionOutcome.CONFIRM if matching_rule.require_confirmation else DecisionOutcome.ALLOW
        reason_code = ReasonCode.CONFIRM_HIGH_RISK if outcome == DecisionOutcome.CONFIRM else ReasonCode.ALLOWED_BY_POLICY
        
        return PolicyDecision(
            outcome=outcome,
            reason_code=reason_code,
            explanation=f"Allowed by rule: {matching_rule.name}",
            matched_rule=matching_rule.name,
            risk_tier=risk_tier,
            required_evidence=required_evidence
        )

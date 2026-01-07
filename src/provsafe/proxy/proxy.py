"""Tool-call proxy with policy enforcement."""

import time
from typing import Optional, Dict, Any
from datetime import datetime

from .schema import (
    ToolCallRequest,
    PolicyDecision,
    DecisionOutcome,
    ReasonCode,
    RiskTier,
    ToolRegistry,
)


class ToolCallProxy:
    """
    Proxy that validates and enforces policy on tool calls.
    
    Flow:
    1. Validate request against tool schema
    2. Evaluate policy (allowlist, constraints)
    3. Check provenance requirements
    4. Return decision with reason codes
    """
    
    def __init__(self, tool_registry: ToolRegistry, policy_engine, provenance_tracker=None):
        self.tool_registry = tool_registry
        self.policy_engine = policy_engine
        self.provenance_tracker = provenance_tracker
        self._stats = {
            "total_requests": 0,
            "allowed": 0,
            "denied": 0,
            "confirmed": 0,
        }
    
    def validate_request(self, request: ToolCallRequest) -> tuple[bool, Optional[str]]:
        """Validate request against tool schemas."""
        return self.tool_registry.validate_request(request)
    
    def enforce_policy(
        self,
        request: ToolCallRequest,
        user_context: Optional[Dict[str, Any]] = None
    ) -> PolicyDecision:
        """
        Enforce policy on a tool call request.
        
        Args:
            request: Tool call request
            user_context: Additional user/session context
            
        Returns:
            PolicyDecision with outcome and reason codes
        """
        self._stats["total_requests"] += 1
        start_time = time.time()
        
        # 1. Validate against schema
        is_valid, error_msg = self.validate_request(request)
        if not is_valid:
            decision = PolicyDecision(
                outcome=DecisionOutcome.DENY,
                reason_code=ReasonCode.DENIED_NO_RULE,
                explanation=f"Schema validation failed: {error_msg}",
                metadata={"validation_error": error_msg}
            )
            self._record_decision(decision)
            return decision
        
        # 2. Get risk tier from schema
        schema = self.tool_registry.get_schema(request.tool)
        action_schema = schema.get_action_schema(request.action) if schema else None
        risk_tier = action_schema.risk_tier if action_schema else RiskTier.MEDIUM
        
        # 3. Evaluate policy
        decision = self.policy_engine.evaluate(
            request=request,
            risk_tier=risk_tier,
            user_context=user_context or {}
        )
        
        # 4. Track provenance if enabled
        if self.provenance_tracker and decision.outcome == DecisionOutcome.ALLOW:
            self.provenance_tracker.log_tool_call(
                request=request,
                decision=decision,
                timestamp=datetime.now()
            )
        
        # 5. Add latency metadata
        decision.metadata["latency_ms"] = (time.time() - start_time) * 1000
        
        self._record_decision(decision)
        return decision
    
    def _record_decision(self, decision: PolicyDecision):
        """Record decision in statistics."""
        if decision.outcome == DecisionOutcome.ALLOW:
            self._stats["allowed"] += 1
        elif decision.outcome == DecisionOutcome.DENY:
            self._stats["denied"] += 1
        elif decision.outcome == DecisionOutcome.CONFIRM:
            self._stats["confirmed"] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get proxy statistics."""
        return self._stats.copy()
    
    def reset_stats(self):
        """Reset statistics counters."""
        self._stats = {
            "total_requests": 0,
            "allowed": 0,
            "denied": 0,
            "confirmed": 0,
        }

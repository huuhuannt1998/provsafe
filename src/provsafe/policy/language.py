"""Policy language structures and YAML parsing."""

from typing import List, Dict, Any, Optional
from datetime import time as time_type
from pydantic import BaseModel, Field
import yaml


class TimeConstraint(BaseModel):
    """Time-of-day constraint."""
    start_time: str = Field(..., description="Start time in HH:MM format")
    end_time: str = Field(..., description="End time in HH:MM format")
    days: List[str] = Field(default_factory=lambda: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"])
    
    def is_allowed(self, current_time: time_type, current_day: str) -> bool:
        """Check if current time is within allowed window."""
        if current_day.lower() not in [d.lower() for d in self.days]:
            return False
        
        start = time_type.fromisoformat(self.start_time)
        end = time_type.fromisoformat(self.end_time)
        
        if start <= end:
            return start <= current_time <= end
        else:  # Crosses midnight
            return current_time >= start or current_time <= end


class RateLimitConstraint(BaseModel):
    """Rate limiting constraint."""
    max_calls: int = Field(..., description="Maximum number of calls")
    window_seconds: int = Field(..., description="Time window in seconds")
    scope: str = Field(default="user", description="Scope: 'user', 'session', 'global'")


class ScopeConstraint(BaseModel):
    """Resource scope constraint."""
    allowed_patterns: List[str] = Field(default_factory=list, description="Allowed resource patterns (regex)")
    denied_patterns: List[str] = Field(default_factory=list, description="Denied resource patterns (regex)")


class EvidenceRequirement(BaseModel):
    """Evidence requirement for high-risk actions."""
    min_trusted_sources: int = Field(default=1, description="Minimum trusted input sources")
    require_user_confirmation: bool = Field(default=False)
    max_derivation_depth: Optional[int] = Field(default=None, description="Max hops from trusted input")


class PolicyRule(BaseModel):
    """Single policy rule."""
    name: str
    description: Optional[str] = None
    tool: str = Field(..., description="Tool name or pattern (* for wildcard)")
    action: str = Field(..., description="Action name or pattern (* for wildcard)")
    resource_pattern: Optional[str] = Field(default=None, description="Resource pattern (regex)")
    risk_tier: Optional[str] = None
    
    # Constraints
    time_constraints: List[TimeConstraint] = Field(default_factory=list)
    rate_limit: Optional[RateLimitConstraint] = None
    scope: Optional[ScopeConstraint] = None
    evidence_requirements: Optional[EvidenceRequirement] = None
    
    # Outcome
    allow: bool = Field(default=True, description="Whether to allow if matched")
    require_confirmation: bool = Field(default=False)
    
    def matches(self, tool: str, action: str, resource: Optional[str] = None) -> bool:
        """Check if this rule matches the request."""
        import re
        
        # Tool matching
        if self.tool != "*" and self.tool != tool:
            return False
        
        # Action matching
        if self.action != "*" and self.action != action:
            return False
        
        # Resource pattern matching
        if self.resource_pattern and resource:
            if not re.match(self.resource_pattern, resource):
                return False
        
        return True


class CapabilityPolicy(BaseModel):
    """Complete capability policy."""
    version: str = "1.0"
    name: str
    description: Optional[str] = None
    
    # Default behavior
    default_allow: bool = Field(default=False, description="Default if no rules match")
    
    # Rules (evaluated in order)
    rules: List[PolicyRule] = Field(default_factory=list)
    
    # Global constraints
    global_rate_limit: Optional[RateLimitConstraint] = None
    
    @classmethod
    def from_yaml(cls, yaml_path: str) -> "CapabilityPolicy":
        """Load policy from YAML file."""
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        return cls(**data)
    
    def to_yaml(self, yaml_path: str):
        """Save policy to YAML file."""
        with open(yaml_path, 'w') as f:
            yaml.dump(self.model_dump(exclude_none=True), f, sort_keys=False)
    
    def find_matching_rule(self, tool: str, action: str, resource: Optional[str] = None) -> Optional[PolicyRule]:
        """Find the first matching rule."""
        for rule in self.rules:
            if rule.matches(tool, action, resource):
                return rule
        return None

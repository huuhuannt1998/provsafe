"""Tool schema definitions and validation."""

from typing import Any, Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field


class RiskTier(str, Enum):
    """Risk classification for tool actions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolAction(str, Enum):
    """Standard tool actions."""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    CREATE = "create"
    UPDATE = "update"
    LIST = "list"


class ToolCallRequest(BaseModel):
    """Incoming tool-call request from agent."""
    tool: str = Field(..., description="Tool name (e.g., 'file_system', 'calendar')")
    action: str = Field(..., description="Action to perform (e.g., 'read', 'write')")
    resource: str = Field(..., description="Target resource (e.g., file path, calendar ID)")
    args: Dict[str, Any] = Field(default_factory=dict, description="Additional arguments")
    context: Dict[str, Any] = Field(default_factory=dict, description="Request context (user_id, session, etc.)")
    
    class Config:
        extra = "allow"


class DecisionOutcome(str, Enum):
    """Policy decision outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    CONFIRM = "confirm"  # Requires user confirmation


class ReasonCode(str, Enum):
    """Standardized reason codes for policy decisions."""
    # Allow reasons
    ALLOWED_BY_POLICY = "allowed_by_policy"
    ALLOWED_WITH_CONSTRAINTS = "allowed_with_constraints"
    
    # Deny reasons
    DENIED_NO_RULE = "denied_no_rule"
    DENIED_BLACKLIST = "denied_blacklist"
    DENIED_RATE_LIMIT = "denied_rate_limit"
    DENIED_TIME_CONSTRAINT = "denied_time_constraint"
    DENIED_SCOPE_VIOLATION = "denied_scope_violation"
    DENIED_RISK_TOO_HIGH = "denied_risk_too_high"
    DENIED_MISSING_EVIDENCE = "denied_missing_evidence"
    
    # Confirm reasons
    CONFIRM_HIGH_RISK = "confirm_high_risk"
    CONFIRM_INSUFFICIENT_EVIDENCE = "confirm_insufficient_evidence"
    CONFIRM_FIRST_USE = "confirm_first_use"


class PolicyDecision(BaseModel):
    """Policy enforcement decision with provenance."""
    outcome: DecisionOutcome
    reason_code: ReasonCode
    explanation: str
    matched_rule: Optional[str] = None
    risk_tier: Optional[RiskTier] = None
    required_evidence: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolParameter(BaseModel):
    """Tool parameter schema definition."""
    name: str
    type: str  # "string", "integer", "boolean", "object", "array"
    required: bool = True
    description: Optional[str] = None
    default: Optional[Any] = None


class ToolActionSchema(BaseModel):
    """Schema for a specific tool action."""
    action: str
    description: str
    risk_tier: RiskTier = RiskTier.LOW
    parameters: List[ToolParameter] = Field(default_factory=list)
    requires_resource: bool = True


class ToolSchema(BaseModel):
    """Complete schema for a tool."""
    name: str
    description: str
    version: str = "1.0.0"
    actions: List[ToolActionSchema]
    
    def get_action_schema(self, action: str) -> Optional[ToolActionSchema]:
        """Get schema for a specific action."""
        for act in self.actions:
            if act.action == action:
                return act
        return None
    
    def validate_action(self, action: str) -> bool:
        """Check if action is valid for this tool."""
        return any(act.action == action for act in self.actions)


class ToolRegistry:
    """Registry of available tools and their schemas."""
    
    def __init__(self):
        self.tools: Dict[str, ToolSchema] = {}
    
    def register(self, schema: ToolSchema):
        """Register a tool schema."""
        self.tools[schema.name] = schema
    
    def get_schema(self, tool: str) -> Optional[ToolSchema]:
        """Get schema for a tool."""
        return self.tools.get(tool)
    
    def validate_request(self, request: ToolCallRequest) -> tuple[bool, Optional[str]]:
        """Validate a tool call request against schemas.
        
        Returns:
            (is_valid, error_message)
        """
        schema = self.get_schema(request.tool)
        if not schema:
            return False, f"Unknown tool: {request.tool}"
        
        if not schema.validate_action(request.action):
            return False, f"Invalid action '{request.action}' for tool '{request.tool}'"
        
        action_schema = schema.get_action_schema(request.action)
        if action_schema and action_schema.requires_resource and not request.resource:
            return False, f"Action '{request.action}' requires a resource"
        
        return True, None

"""Benchmark task definitions and test cases."""

from typing import List, Dict, Any, Optional
from enum import Enum
from pydantic import BaseModel, Field
import yaml


class TaskType(str, Enum):
    """Type of benchmark task."""
    BENIGN = "benign"  # Normal legitimate use
    ATTACK = "attack"  # Prompt injection attack


class ExpectedOutcome(str, Enum):
    """Expected policy decision outcome."""
    ALLOW = "allow"
    DENY = "deny"
    CONFIRM = "confirm"


class ToolCallSpec(BaseModel):
    """Specification for a single tool call."""
    tool: str
    action: str
    resource: str
    args: Dict[str, Any] = Field(default_factory=dict)
    expected_outcome: ExpectedOutcome
    
    # For attacks: whether executing this call constitutes success
    is_attack_goal: bool = Field(default=False)


class BenchmarkTask(BaseModel):
    """Single benchmark task or attack scenario."""
    id: str
    name: str
    description: str
    task_type: TaskType
    
    # Input context
    user_input: str  # The prompt/input that triggers this scenario
    trusted_context: List[str] = Field(default_factory=list)  # Trusted background info
    
    # Expected tool calls
    tool_calls: List[ToolCallSpec]
    
    # Success criteria
    success_criteria: str
    
    # Metadata
    risk_level: str = Field(default="medium")
    tags: List[str] = Field(default_factory=list)


class BenchmarkSuite(BaseModel):
    """Collection of benchmark tasks."""
    name: str
    version: str = "1.0"
    description: Optional[str] = None
    tasks: List[BenchmarkTask] = Field(default_factory=list)
    
    @classmethod
    def from_yaml(cls, yaml_path: str) -> "BenchmarkSuite":
        """Load benchmark suite from YAML."""
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        return cls(**data)
    
    def to_yaml(self, yaml_path: str):
        """Save benchmark suite to YAML."""
        with open(yaml_path, 'w') as f:
            yaml.dump(self.model_dump(exclude_none=True), f, sort_keys=False)
    
    def get_benign_tasks(self) -> List[BenchmarkTask]:
        """Get only benign tasks."""
        return [t for t in self.tasks if t.task_type == TaskType.BENIGN]
    
    def get_attack_tasks(self) -> List[BenchmarkTask]:
        """Get only attack tasks."""
        return [t for t in self.tasks if t.task_type == TaskType.ATTACK]

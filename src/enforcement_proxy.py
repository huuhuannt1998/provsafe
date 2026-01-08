#!/usr/bin/env python3
"""
PROVSAFE Enforcement Proxy

Intercepts tool calls from LLM agents, evaluates policies with provenance context,
and enforces security decisions (allow/deny/confirm).
"""

import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from enum import Enum

from .provenance_graph import ProvenanceGraph, TrustLabel
from .policy_engine import PolicyEngine, PolicyDecision, PolicyEvaluationResult


class ExecutionResult(Enum):
    """Tool execution results."""
    ALLOWED = "allowed"              # Executed successfully
    DENIED = "denied"                # Blocked by policy
    CONFIRMED = "confirmed"          # User approved
    REJECTED = "rejected"            # User rejected
    ERROR = "error"                  # Execution error


@dataclass
class ToolCallLog:
    """Log entry for a tool call."""
    timestamp: datetime
    tool_name: str
    tool_args: Dict[str, Any]
    policy_decision: str
    execution_result: str
    provenance_summary: Dict[str, Any]
    policy_latency_ms: float
    tool_latency_ms: Optional[float]
    user_confirmed: Optional[bool]
    error: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result


class EnforcementProxy:
    """
    Tool-call enforcement proxy that:
    1. Intercepts tool calls from LLM agent
    2. Traces argument provenance
    3. Evaluates policies
    4. Prompts for user confirmation if needed
    5. Logs all decisions
    """
    
    def __init__(
        self,
        provenance_graph: ProvenanceGraph,
        policy_engine: PolicyEngine,
        tool_registry: Dict[str, Callable],
        confirmation_handler: Optional[Callable] = None,
        log_file: Optional[str] = None
    ):
        """
        Initialize enforcement proxy.
        
        Args:
            provenance_graph: Provenance tracking system
            policy_engine: Policy evaluation engine
            tool_registry: Dict mapping tool names to callable functions
            confirmation_handler: Function that prompts user for confirmation
            log_file: Path to log file for audit trail
        """
        self.provenance = provenance_graph
        self.policy_engine = policy_engine
        self.tool_registry = tool_registry
        self.confirmation_handler = confirmation_handler or self._default_confirmation
        self.log_file = log_file
        self.call_logs: List[ToolCallLog] = []
        
        # Statistics
        self.stats = {
            "total_calls": 0,
            "allowed": 0,
            "denied": 0,
            "confirmed": 0,
            "rejected": 0,
            "errors": 0,
        }
    
    def intercept_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        llm_reasoning_node_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Intercept and evaluate a tool call before execution.
        
        Args:
            tool_name: Name of the tool to execute
            tool_args: Arguments for the tool
            llm_reasoning_node_id: Provenance node ID for the LLM reasoning that generated this call
            metadata: Additional context
            
        Returns:
            {
                "allowed": bool,
                "result": Any,  # Tool output if allowed, None otherwise
                "decision": PolicyDecision,
                "reason": str,
                "provenance": Dict,
                "latency": Dict,
            }
        """
        start_time = time.time()
        self.stats["total_calls"] += 1
        
        metadata = metadata or {}
        
        # Step 1: Add tool call to provenance graph
        tool_call_node_id = self.provenance.add_tool_call(
            tool_name=tool_name,
            arguments=tool_args,
            reasoning_node_id=llm_reasoning_node_id,
            metadata=metadata,
        )
        
        # Step 2: Argument validation (detect obfuscation/encoding attacks)
        validation_issue = self._validate_arguments(tool_args)
        if validation_issue:
            # Deny immediately if suspicious arguments detected
            # Note: PolicyDecision is already imported at module level
            policy_result = type('obj', (object,), {
                'decision': PolicyDecision.DENY,
                'reason': f"Suspicious argument detected: {validation_issue}",
                'matched_rule': None,
                'requires_confirmation': False,
                'metadata': {}
            })()
            policy_latency_ms = 0.0
            prov_latency_ms = 0.0
            provenance_info = {"has_untrusted_args": False, "untrusted_arg_names": []}
        else:
            # Step 3: Trace argument provenance
            prov_start = time.time()
            provenance_info = self.provenance.trace_argument_provenance(tool_args)
            prov_latency_ms = (time.time() - prov_start) * 1000
            
            # Step 4: Evaluate policy
            policy_start = time.time()
            policy_result = self.policy_engine.evaluate(
                tool_name=tool_name,
                tool_args=tool_args,
                provenance_info=provenance_info,
            )
            policy_latency_ms = (time.time() - policy_start) * 1000
        
        # Step 4: Handle decision
        execution_result = None
        tool_output = None
        tool_latency_ms = None
        user_confirmed = None
        error_msg = None
        
        if policy_result.decision == PolicyDecision.ALLOW:
            # Execute without confirmation
            execution_result = ExecutionResult.ALLOWED
            tool_output, tool_latency_ms, error_msg = self._execute_tool(tool_name, tool_args)
            self.stats["allowed"] += 1
            
        elif policy_result.decision == PolicyDecision.DENY:
            # Block execution
            execution_result = ExecutionResult.DENIED
            self.stats["denied"] += 1
            
        elif policy_result.decision == PolicyDecision.REQUIRE_CONFIRMATION:
            # Prompt user for confirmation
            user_approved = self.confirmation_handler(
                tool_name=tool_name,
                tool_args=tool_args,
                reason=policy_result.reason,
                provenance=provenance_info,
            )
            
            user_confirmed = user_approved
            
            if user_approved:
                execution_result = ExecutionResult.CONFIRMED
                tool_output, tool_latency_ms, error_msg = self._execute_tool(tool_name, tool_args)
                self.stats["confirmed"] += 1
            else:
                execution_result = ExecutionResult.REJECTED
                self.stats["rejected"] += 1
        
        # Step 5: Add tool result to provenance (if executed)
        if tool_output is not None and execution_result in [ExecutionResult.ALLOWED, ExecutionResult.CONFIRMED]:
            # Mark tool results as untrusted (external data) unless it's a trusted system tool
            is_trusted_tool = self._is_trusted_tool(tool_name)
            self.provenance.add_tool_result(
                tool_name=tool_name,
                tool_output=tool_output,
                is_trusted_tool=is_trusted_tool,
                metadata={"tool_call_node_id": tool_call_node_id},
            )
        
        # Step 6: Log the call
        log_entry = ToolCallLog(
            timestamp=datetime.now(),
            tool_name=tool_name,
            tool_args=tool_args,
            policy_decision=policy_result.decision.value,
            execution_result=execution_result.value,
            provenance_summary={
                "has_untrusted_args": provenance_info["has_untrusted_args"],
                "untrusted_args": provenance_info["untrusted_arg_names"],
            },
            policy_latency_ms=policy_latency_ms,
            tool_latency_ms=tool_latency_ms,
            user_confirmed=user_confirmed,
            error=error_msg,
        )
        self.call_logs.append(log_entry)
        self._write_log(log_entry)
        
        total_latency_ms = (time.time() - start_time) * 1000
        
        # Return result
        return {
            "allowed": execution_result in [ExecutionResult.ALLOWED, ExecutionResult.CONFIRMED],
            "result": tool_output,
            "decision": policy_result.decision.value,
            "execution_result": execution_result.value,
            "reason": policy_result.reason,
            "provenance": provenance_info,
            "latency": {
                "total_ms": total_latency_ms,
                "provenance_ms": prov_latency_ms,
                "policy_ms": policy_latency_ms,
                "tool_ms": tool_latency_ms,
            },
            "metadata": policy_result.metadata,
        }
    
    def _execute_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> tuple[Any, float, Optional[str]]:
        """
        Execute the actual tool function.
        
        Returns:
            (output, latency_ms, error_message)
        """
        if tool_name not in self.tool_registry:
            error_msg = f"Tool {tool_name} not found in registry"
            return None, 0.0, error_msg
        
        tool_func = self.tool_registry[tool_name]
        
        start_time = time.time()
        try:
            output = tool_func(**tool_args)
            latency_ms = (time.time() - start_time) * 1000
            return output, latency_ms, None
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            error_msg = f"Tool execution error: {str(e)}"
            self.stats["errors"] += 1
            return None, latency_ms, error_msg
    
    def _is_trusted_tool(self, tool_name: str) -> bool:
        """Check if a tool produces trusted output."""
        # System configuration tools are trusted
        trusted_tools = ["system.get_config", "user.get_profile", "auth.get_token"]
        return tool_name in trusted_tools
    
    def _default_confirmation(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        reason: str,
        provenance: Dict[str, Any]
    ) -> bool:
        """
        Default confirmation handler (command-line prompt).
        Can be overridden with custom UI.
        """
        print(f"\n{'='*60}")
        print(f"PROVSAFE CONFIRMATION REQUIRED")
        print(f"{'='*60}")
        print(f"Tool: {tool_name}")
        print(f"Arguments: {json.dumps(tool_args, indent=2)}")
        print(f"Reason: {reason}")
        
        if provenance["has_untrusted_args"]:
            print(f"\n⚠️  WARNING: The following arguments trace to UNTRUSTED sources:")
            for arg_name in provenance["untrusted_arg_names"]:
                print(f"  - {arg_name}")
        
        print(f"\n{'='*60}")
        response = input("Allow this tool call? (yes/no): ").strip().lower()
        return response in ["yes", "y"]
    
    def _write_log(self, log_entry: ToolCallLog):
        """Write log entry to file."""
        if not self.log_file:
            return
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry.to_dict()) + "\n")
        except Exception as e:
            print(f"Warning: Failed to write log: {e}")
    
    def _validate_arguments(self, tool_args: Dict[str, Any]) -> Optional[str]:
        """
        Validate tool arguments for common attack patterns.
        
        Returns:
            None if arguments are valid, error message if suspicious
        """
        import re
        import base64
        import codecs
        import unicodedata
        
        for arg_name, arg_value in tool_args.items():
            if not isinstance(arg_value, str):
                # Check numeric values for extreme settings
                if arg_name == 'temperature' and isinstance(arg_value, (int, float)):
                    if arg_value > 85 or arg_value < 55:
                        return f"Extreme temperature value: {arg_value}"
                continue
            
            # Normalize unicode to catch obfuscation
            normalized = unicodedata.normalize('NFKD', arg_value).encode('ascii', 'ignore').decode('ascii')
            
            # Check for encoding/obfuscation
            # 1. Base64 encoded content
            if len(arg_value) > 20 and self._looks_like_base64(arg_value):
                try:
                    decoded = base64.b64decode(arg_value).decode('utf-8', errors='ignore')
                    if any(word in decoded.lower() for word in ['delete', 'remove', 'drop', 'rm ', 'format', 'wipe', 'unlock']):
                        return f"Base64-encoded dangerous command in {arg_name}"
                except:
                    pass
            
            # 2. Hex encoding
            if re.match(r'^[0-9a-fA-F]{20,}$', arg_value):
                try:
                    decoded = bytes.fromhex(arg_value).decode('utf-8', errors='ignore')
                    if any(word in decoded.lower() for word in ['delete', 'remove', 'drop', 'rm ', 'format', 'unlock']):
                        return f"Hex-encoded dangerous command in {arg_name}"
                except:
                    pass
            
            # 3. ROT13 encoding
            try:
                rot13_decoded = codecs.decode(arg_value, 'rot_13')
                if any(word in rot13_decoded.lower() for word in ['delete', 'remove', 'unlock', 'format']):
                    return f"ROT13-encoded dangerous command in {arg_name}"
            except:
                pass
            
            # 4. Path traversal
            if '..' in arg_value or arg_value.startswith('/etc') or arg_value.startswith('/root') or arg_value.startswith('/sys') or arg_value.startswith('/bin'):
                return f"Path traversal or system path in {arg_name}"
            
            # 5. Command injection patterns
            if any(char in arg_value for char in ['|', ';', '&', '$(', '`']):
                return f"Shell metacharacters in {arg_name}"
            
            # 6. Stricter length limits (reduced from 500 to 200)
            if len(arg_value) > 200:
                return f"Abnormally long argument {arg_name} ({len(arg_value)} chars)"
            
            # 7. URL encoding check
            if '%' in arg_value and len(arg_value) > 20:
                url_decoded = arg_value.replace('%20', ' ').replace('%2F', '/').replace('%3B', ';')
                if url_decoded != arg_value and any(word in url_decoded.lower() for word in ['delete', 'drop', 'format', 'unlock']):
                    return f"URL-encoded dangerous command in {arg_name}"
            
            # 8. Dangerous keywords even in normalized text
            dangerous_keywords = ['password', 'passwd', 'shadow', 'sudoers', 'authorized_keys']
            if any(keyword in normalized.lower() for keyword in dangerous_keywords):
                return f"Sensitive path/file keyword in {arg_name}"
        
        return None
    
    def _looks_like_base64(self, s: str) -> bool:
        """Check if string looks like base64 encoding."""
        # Base64 uses A-Z, a-z, 0-9, +, /, = and has length multiple of 4
        if len(s) % 4 != 0:
            return False
        import re
        return bool(re.match(r'^[A-Za-z0-9+/]+={0,2}$', s))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get enforcement statistics."""
        return {
            **self.stats,
            "provenance_stats": self.provenance.get_statistics(),
            "confirmation_rate": (
                self.stats["confirmed"] / self.stats["total_calls"]
                if self.stats["total_calls"] > 0 else 0
            ),
            "denial_rate": (
                self.stats["denied"] / self.stats["total_calls"]
                if self.stats["total_calls"] > 0 else 0
            ),
        }
    
    def export_logs(self, filepath: str):
        """Export all call logs to JSON file."""
        with open(filepath, 'w') as f:
            logs = [log.to_dict() for log in self.call_logs]
            json.dump(logs, f, indent=2)

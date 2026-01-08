#!/usr/bin/env python3
"""
PROVSAFE LLM Agent Integration

Provides a wrapper around LLM agents that integrates with the enforcement proxy.
Supports function calling / tool use with real LLMs.
"""

import json
import re
import requests
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass

from .provenance_graph import ProvenanceGraph
from .enforcement_proxy import EnforcementProxy


@dataclass
class ToolDefinition:
    """Definition of a tool that can be called by the LLM."""
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema
    function: Callable
    risk_tier: str = "MEDIUM"


class LLMAgent:
    """
    LLM agent with PROVSAFE enforcement.
    
    Workflow:
    1. User provides input (TRUSTED)
    2. Agent calls LLM with tools + conversation history
    3. LLM generates tool calls
    4. Each tool call goes through EnforcementProxy
    5. Tool results added to provenance (UNTRUSTED)
    6. Loop until LLM completes or max iterations
    """
    
    def __init__(
        self,
        model: str,
        api_url: str,
        api_key: str,
        provenance: ProvenanceGraph,
        enforcement_proxy: EnforcementProxy,
        tools: List[ToolDefinition],
        max_iterations: int = 5,
        temperature: float = 0.0,
    ):
        """
        Initialize LLM agent.
        
        Args:
            model: Model name (e.g., "openai/gpt-oss-120b")
            api_url: LLM API endpoint
            api_key: API key for authentication
            provenance: Provenance graph
            enforcement_proxy: Enforcement proxy
            tools: List of available tools
            max_iterations: Max agent loops
            temperature: LLM sampling temperature
        """
        self.model = model
        self.api_url = api_url
        self.api_key = api_key
        self.provenance = provenance
        self.enforcement_proxy = enforcement_proxy
        self.tools = {tool.name: tool for tool in tools}
        self.max_iterations = max_iterations
        self.temperature = temperature
        
        # Conversation history with provenance tracking
        self.conversation: List[Dict[str, Any]] = []
        self.conversation_node_ids: List[str] = []
        
        # System prompt
        self.system_prompt = self._build_system_prompt()
    
    def _build_system_prompt(self) -> str:
        """Build system prompt with tool descriptions."""
        tool_descriptions = []
        for tool in self.tools.values():
            params = json.dumps(tool.parameters, indent=2)
            tool_descriptions.append(
                f"- {tool.name}: {tool.description}\n  Parameters: {params}"
            )
        
        tools_text = "\n".join(tool_descriptions)
        
        return f"""You are a helpful AI assistant with access to the following tools:

{tools_text}

To use a tool, respond with a JSON object in this format:
{{"tool": "tool_name", "arguments": {{"arg1": "value1", "arg2": "value2"}}}}

If you need to call multiple tools, make one call at a time and wait for results.
When you have completed the user's request, respond with plain text (no JSON).
"""
    
    def run(self, user_input: str) -> str:
        """
        Run the agent on a user input.
        
        Args:
            user_input: User's request
            
        Returns:
            Final response from the agent
        """
        # Check for jailbreak attempts BEFORE processing
        jailbreak_detected = self._detect_jailbreak(user_input)
        if jailbreak_detected:
            return f"Request rejected: {jailbreak_detected}"
        
        # Check for multi-turn chaining patterns
        chaining_detected = self._detect_chaining(user_input)
        if chaining_detected:
            return f"Request rejected: {chaining_detected}"
        
        # Add user input to provenance as TRUSTED
        user_node_id = self.provenance.add_user_input(user_input)
        
        # Add to conversation
        self.conversation.append({
            "role": "user",
            "content": user_input,
        })
        self.conversation_node_ids.append(user_node_id)
        
        # Agent loop
        for iteration in range(self.max_iterations):
            # Call LLM
            llm_response = self._call_llm()
            
            # Add LLM response to provenance
            llm_node_id = self.provenance.add_llm_generation(
                llm_output=llm_response,
                source_node_ids=self.conversation_node_ids,
                metadata={"iteration": iteration, "model": self.model},
            )
            
            # Check if response contains tool call
            tool_call = self._parse_tool_call(llm_response)
            
            if tool_call is None:
                # No tool call - agent is done
                self.conversation.append({
                    "role": "assistant",
                    "content": llm_response,
                })
                return llm_response
            
            # Execute tool call through enforcement proxy
            result = self._execute_tool_call(tool_call, llm_node_id)
            
            # Add tool result to conversation
            if result["allowed"]:
                tool_output = result["result"]
                status = "✓ Executed"
            else:
                tool_output = f"[BLOCKED: {result['reason']}]"
                status = "✗ Blocked"
            
            # Add to conversation
            self.conversation.append({
                "role": "assistant",
                "content": f"[Tool Call: {tool_call['tool']}]\n{json.dumps(tool_call['arguments'])}",
            })
            self.conversation.append({
                "role": "system",
                "content": f"{status}\nResult: {json.dumps(tool_output)[:500]}",
            })
            
            # The tool result node was already added by enforcement proxy
            # Find it and add to conversation tracking
            # For simplicity, we'll just track the LLM node
            self.conversation_node_ids.append(llm_node_id)
        
        # Max iterations reached
        return "Maximum iterations reached. Please refine your request."
    
    def _call_llm(self) -> str:
        """
        Call the LLM API with tool calling support.
        
        Uses text-based tool calling for models that don't support native OpenAI-style tools.
        Returns either text response or tool call in standardized format.
        """
        # Import here to avoid circular dependency
        import sys
        from pathlib import Path
        eval_path = Path(__file__).parent.parent / "evaluation"
        if str(eval_path) not in sys.path:
            sys.path.insert(0, str(eval_path))
        
        try:
            from baseline_systems import call_llm_direct
        except ImportError:
            # Fallback if baseline_systems not available
            return self._call_llm_fallback()
        
        messages = [
            {"role": "system", "content": self.system_prompt},
            *self.conversation
        ]
        
        # Convert ToolDefinitions to API format
        # self.tools is a dict {name: ToolDefinition}, iterate over values
        tools = []
        for tool_def in self.tools.values():
            tools.append({
                "type": "function",
                "function": {
                    "name": tool_def.name,
                    "description": tool_def.description,
                    "parameters": tool_def.parameters
                }
            })
        
        try:
            result = call_llm_direct(self.model, self.api_url, self.api_key, messages, tools)
            
            # Extract response
            if "choices" in result and len(result["choices"]) > 0:
                message = result["choices"][0]["message"]
                
                # Check for tool calls first
                if "tool_calls" in message and message["tool_calls"]:
                    # Return tool call in expected format
                    tool_call = message["tool_calls"][0]
                    func = tool_call["function"]
                    return json.dumps({
                        "tool": func["name"],
                        "arguments": json.loads(func["arguments"]) if isinstance(func["arguments"], str) else func["arguments"]
                    })
                
                # Otherwise return content
                return message.get("content", "") or ""
            
            return "[LLM Error: No response content]"
            
        except Exception as e:
            return f"[LLM Error: {str(e)}]"
    
    def _call_llm_fallback(self) -> str:
        """Fallback LLM call without text-based tool calling support."""
        messages = [
            {"role": "system", "content": self.system_prompt},
            *self.conversation
        ]
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": 2000,
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        
        try:
            response = requests.post(
                self.api_url,
                json=payload,
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Extract content from response
            if "choices" in data and len(data["choices"]) > 0:
                return data["choices"][0]["message"]["content"]
            
            return "[LLM Error: No response content]"
            
        except Exception as e:
            return f"[LLM Error: {str(e)}]"
    
    def _parse_tool_call(self, llm_response: str) -> Optional[Dict[str, Any]]:
        """
        Parse tool call from LLM response.
        
        Expected format: {"tool": "tool_name", "arguments": {...}}
        """
        # Try to parse response as JSON directly
        try:
            tool_call = json.loads(llm_response.strip())
            if isinstance(tool_call, dict) and "tool" in tool_call and "arguments" in tool_call:
                return tool_call
        except json.JSONDecodeError:
            pass
        
        # Try to find JSON object in response text
        try:
            # Use a more flexible pattern that handles nested braces
            # Look for content between the outermost braces that contains "tool"
            if '"tool"' in llm_response:
                # Find first { and last }
                start = llm_response.find('{')
                end = llm_response.rfind('}')
                if start != -1 and end != -1 and end > start:
                    json_str = llm_response[start:end+1]
                    tool_call = json.loads(json_str)
                    if isinstance(tool_call, dict) and "tool" in tool_call and "arguments" in tool_call:
                        return tool_call
        except json.JSONDecodeError:
            pass
        
        return None
    
    def _execute_tool_call(self, tool_call: Dict[str, Any], llm_node_id: str) -> Dict[str, Any]:
        """Execute tool call through enforcement proxy."""
        tool_name = tool_call["tool"]
        tool_args = tool_call["arguments"]
        
        # Pass through enforcement proxy
        result = self.enforcement_proxy.intercept_tool_call(
            tool_name=tool_name,
            tool_args=tool_args,
            llm_reasoning_node_id=llm_node_id,
            metadata={"model": self.model},
        )
        
        return result
    
    def reset(self):
        """Reset conversation history."""
        self.conversation = []
        self.conversation_node_ids = []
    def _looks_like_base64(self, s: str) -> bool:
        """Check if string looks like base64 encoding."""
        if len(s) % 4 != 0:
            return False
        import re
        return bool(re.match(r'^[A-Za-z0-9+/]+={0,2}$', s))
    
    def _detect_jailbreak(self, user_input: str) -> Optional[str]:
        """
        Detect jailbreak attempts in user input.
        
        Returns:
            Error message if jailbreak detected, None otherwise
        """
        text_lower = user_input.lower()
        
        # Jailbreak patterns
        jailbreak_patterns = [
            (r'ignore (previous|all|prior) (instructions|rules|guidelines)', 'Instruction override attempt'),
            (r'(pretend|imagine|roleplay|act as if).*(debug|developer|admin|unrestricted|god) mode', 'Roleplay jailbreak'),
            (r'(disable|turn off|bypass|skip) (safety|security|filters|checks)', 'Safety bypass attempt'),
            (r'you (are|is) (now|in) (unrestricted|jailbroken|developer) mode', 'Mode manipulation'),
            (r'from now on.*no (restrictions|limits|safety)', 'Restriction removal'),
            (r'[Dd][Aa][Nn]', 'DAN jailbreak variant'),  # Do Anything Now
        ]
        
        for pattern, reason in jailbreak_patterns:
            if re.search(pattern, text_lower):
                return f"Jailbreak detected: {reason}"
        
        return None
    
    def _detect_chaining(self, user_input: str) -> Optional[str]:
        """
        Detect multi-turn chaining attacks.
        
        Returns:
            Error message if chaining detected, None otherwise
        """
        text_lower = user_input.lower()
        
        # Check for suspicious multi-step patterns
        chaining_patterns = [
            r'first.*then.*',
            r'step 1.*step 2',
            r'after.*do.*',
            r'once.*then.*',
        ]
        
        # Only flag if combined with dangerous actions
        has_chaining = any(re.search(p, text_lower) for p in chaining_patterns)
        has_danger = any(word in text_lower for word in ['unlock', 'delete', 'remove', 'disable'])
        
        if has_chaining and has_danger:
            return "Multi-step attack pattern detected"
        
        # Check conversation history for escalation
        if len(self.conversation) > 0:
            recent_requests = ' '.join([msg['content'] for msg in self.conversation[-3:] if msg['role'] == 'user']).lower()
            # Look for progressive privilege escalation
            if 'list' in recent_requests and any(word in user_input.lower() for word in ['unlock', 'delete', 'format']):
                return "Conversation-based escalation detected"
        
        return None


class ToolRegistry:
    """Registry of tools available to LLM agents."""
    
    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}
    
    def register(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        function: Callable,
        risk_tier: str = "MEDIUM",
    ):
        """Register a tool."""
        tool = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters,
            function=function,
            risk_tier=risk_tier,
        )
        self.tools[name] = tool
    
    def get_tool_definitions(self) -> List[ToolDefinition]:
        """Get all tool definitions."""
        return list(self.tools.values())
    
    def get_tool_registry_dict(self) -> Dict[str, Callable]:
        """Get dict of tool names to functions for enforcement proxy."""
        return {name: tool.function for name, tool in self.tools.items()}

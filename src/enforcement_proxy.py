#!/usr/bin/env python3
"""
PROVSAFE Enforcement Proxy

Intercepts tool calls from LLM agents, evaluates policies with provenance context,
and enforces security decisions (allow/deny/confirm).
"""

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from enum import Enum

from .provenance_graph import ProvenanceGraph
from .policy_engine import PolicyEngine, PolicyDecision


class ExecutionResult(Enum):
    """Tool execution results."""

    ALLOWED = "allowed"  # Executed successfully
    DENIED = "denied"  # Blocked by policy
    CONFIRMED = "confirmed"  # User approved
    REJECTED = "rejected"  # User rejected
    ERROR = "error"  # Execution error


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
        log_file: Optional[str] = None,
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
        # SHA-256 hash chain: tracks hash of previous entry for tamper-evidence
        self._prev_log_hash: str = "0" * 64  # genesis sentinel

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
        metadata: Optional[Dict[str, Any]] = None,
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
        # This is a preprocessing step that informs the provenance and policy
        # decisions — it does NOT bypass the policy engine.
        validation_issue = self._validate_arguments(tool_args)

        # Step 3: Trace argument provenance
        prov_start = time.time()
        provenance_info = self.provenance.trace_argument_provenance(tool_args)
        prov_latency_ms = (time.time() - prov_start) * 1000

        # If argument validation detected encoding/obfuscation, mark those
        # arguments as untrusted (they bypassed normal provenance resolution)
        if validation_issue:
            provenance_info["has_untrusted_args"] = True
            provenance_info["validation_issue"] = validation_issue
            # Ensure all args are flagged since we detected obfuscation
            for arg_name in tool_args:
                if arg_name not in provenance_info.get("untrusted_arg_names", []):
                    provenance_info.setdefault("untrusted_arg_names", []).append(arg_name)

        # Step 4: Evaluate policy (always consulted, even with validation issues)
        policy_start = time.time()
        policy_result = self.policy_engine.evaluate(
            tool_name=tool_name,
            tool_args=tool_args,
            provenance_info=provenance_info,
        )
        policy_latency_ms = (time.time() - policy_start) * 1000

        # Step 5: Handle decision
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

        # Step 6: Add tool result to provenance (if executed)
        if tool_output is not None and execution_result in [
            ExecutionResult.ALLOWED,
            ExecutionResult.CONFIRMED,
        ]:
            # Mark tool results as untrusted (external data) unless it's a trusted system tool
            is_trusted_tool = self._is_trusted_tool(tool_name)
            self.provenance.add_tool_result(
                tool_name=tool_name,
                tool_output=tool_output,
                is_trusted_tool=is_trusted_tool,
                metadata={"tool_call_node_id": tool_call_node_id},
            )

        # Step 7: Log the call
        log_entry = ToolCallLog(
            timestamp=datetime.now(),
            tool_name=tool_name,
            tool_args=tool_args,
            policy_decision=policy_result.decision.value,
            execution_result=execution_result.value,
            provenance_summary={
                "has_untrusted_args": provenance_info["has_untrusted_args"],
                "untrusted_args": provenance_info["untrusted_arg_names"],
                "provenance_by_arg": provenance_info.get("provenance_by_arg", {}),
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

    def _execute_tool(
        self, tool_name: str, tool_args: Dict[str, Any]
    ) -> tuple[Any, float, Optional[str]]:
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
        self, tool_name: str, tool_args: Dict[str, Any], reason: str, provenance: Dict[str, Any]
    ) -> bool:
        """
        Default confirmation handler (command-line prompt).
        Can be overridden with custom UI.
        """
        print(f"\n{'='*60}")
        print("PROVSAFE CONFIRMATION REQUIRED")
        print(f"{'='*60}")
        print(f"Tool: {tool_name}")
        print(f"Arguments: {json.dumps(tool_args, indent=2)}")
        print(f"Reason: {reason}")

        if provenance["has_untrusted_args"]:
            print("\n⚠️  WARNING: The following arguments trace to UNTRUSTED sources:")
            for arg_name in provenance["untrusted_arg_names"]:
                print(f"  - {arg_name}")

        print(f"\n{'='*60}")
        response = input("Allow this tool call? (yes/no): ").strip().lower()
        return response in ["yes", "y"]

    def _write_log(self, log_entry: ToolCallLog):
        """Write log entry to file with SHA-256 hash chaining.

        Each entry embeds the SHA-256 hash of the previous serialised entry
        (genesis entry uses 64 zero hex digits).  This makes the audit log
        tamper-evident: any post-hoc modification of an earlier entry breaks
        the hash chain from that point forward.
        """
        if not self.log_file:
            return

        try:
            entry_dict = log_entry.to_dict()
            entry_dict["prev_hash"] = self._prev_log_hash

            # Compute this entry's hash over canonical JSON (sorted keys, no indent)
            serialised = json.dumps(entry_dict, sort_keys=True, separators=(",", ":"))
            entry_hash = hashlib.sha256(serialised.encode("utf-8")).hexdigest()
            entry_dict["entry_hash"] = entry_hash

            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry_dict) + "\n")

            # Advance the chain
            self._prev_log_hash = entry_hash
        except Exception as e:
            print(f"Warning: Failed to write log: {e}")

    def _validate_arguments(self, tool_args: Dict[str, Any]) -> Optional[str]:
        """
        Validate tool arguments for common attack patterns.

        Implements a canonicalization-first approach: every argument is decoded
        through all known encodings before dangerous-keyword checks are applied.
        This closes the encoding-obfuscation gap identified in the evaluation
        (previously 5/10 bypasses used encoded payloads).

        Returns:
            None if arguments are valid, error message if suspicious
        """
        import re
        import base64
        import codecs
        import unicodedata
        import urllib.parse

        DANGEROUS_ACTIONS = [
            "delete",
            "remove",
            "drop",
            "rm ",
            "format",
            "wipe",
            "unlock",
            "reboot",
            "shutdown",
            "kill",
            "truncate",
        ]
        DANGEROUS_PATHS = [
            "/etc/",
            "/root/",
            "/sys/",
            "/bin/",
            "/sbin/",
            "/boot/",
            "/proc/",
            "/dev/",
            "/var/log",
            ".ssh/",
            "authorized_keys",
            "id_rsa",
            "shadow",
            "passwd",
            "sudoers",
        ]

        for arg_name, arg_value in tool_args.items():
            if not isinstance(arg_value, str):
                # Check numeric values for extreme settings
                if arg_name == "temperature" and isinstance(arg_value, (int, float)):
                    if arg_value > 85 or arg_value < 55:
                        return f"Extreme temperature value: {arg_value}"
                continue

            # ── Phase 1: Canonicalize the argument ────────────────────────
            # Build a set of decoded representations to check.
            # Uses iterative multi-pass decoding: each decoded form is fed
            # back through all decoders until no new forms are produced.
            canonical_forms = set()
            canonical_forms.add(arg_value)

            # Also try with leading/trailing whitespace stripped
            stripped = arg_value.strip()
            if stripped != arg_value:
                canonical_forms.add(stripped)

            def _decode_one_pass(value: str) -> set:
                """Apply all single-layer decoders to a value."""
                forms = set()

                # Unicode NFKD normalization
                try:
                    nfkd = unicodedata.normalize("NFKD", value)
                    forms.add(nfkd)
                    ascii_form = nfkd.encode("ascii", "ignore").decode("ascii")
                    forms.add(ascii_form)
                except Exception:
                    pass

                # Inline hex escape sequences: \x2F\x74\x6D\x70 → /tmp
                if "\\x" in value or "\\X" in value:
                    try:
                        # Handle tab-separated or space-separated hex escapes
                        cleaned = re.sub(r"[\t ]+", "", value)
                        hex_decoded = re.sub(
                            r"\\[xX]([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), cleaned
                        )
                        forms.add(hex_decoded)
                    except Exception:
                        pass

                # Inline Unicode escape sequences: \u0064\u0065\u006c → del
                if "\\u" in value or "\\U" in value:
                    try:
                        uni_decoded = re.sub(
                            r"\\[uU]([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), value
                        )
                        forms.add(uni_decoded)
                    except Exception:
                        pass

                # Inline octal escape sequences: \057\164\155\160 → /tmp
                if "\\" in value:
                    try:
                        oct_decoded = re.sub(
                            r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value
                        )
                        if oct_decoded != value:
                            forms.add(oct_decoded)
                    except Exception:
                        pass

                # Base64 decoding (also try stripped version)
                for candidate in [value, value.strip()]:
                    if len(candidate) >= 4 and self._looks_like_base64(candidate):
                        try:
                            decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                            forms.add(decoded)
                        except Exception:
                            pass

                # Pure hex string: 2F746D702F → /tmp/
                if re.match(r"^[0-9a-fA-F]{6,}$", value) and len(value) % 2 == 0:
                    try:
                        decoded = bytes.fromhex(value).decode("utf-8", errors="ignore")
                        forms.add(decoded)
                    except Exception:
                        pass

                # ROT13
                try:
                    rot13_decoded = codecs.decode(value, "rot_13")
                    forms.add(rot13_decoded)
                except Exception:
                    pass

                # URL percent-encoding
                if "%" in value:
                    try:
                        url_decoded = urllib.parse.unquote(value)
                        forms.add(url_decoded)
                        # Double-decode for double-encoded payloads
                        double_decoded = urllib.parse.unquote(url_decoded)
                        if double_decoded != url_decoded:
                            forms.add(double_decoded)
                    except Exception:
                        pass

                # Binary string: 00101111 01110100 → /t...
                if re.match(r"^[01\s]{16,}$", value):
                    try:
                        bits = value.replace(" ", "")
                        chars = [chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits) - 7, 8)]
                        binary_decoded = "".join(chars)
                        forms.add(binary_decoded)
                    except Exception:
                        pass

                # HTML entities: &#47;&#116;&#109;&#112; → /tmp
                if "&#" in value or "&amp;" in value:
                    try:
                        import html

                        html_decoded = html.unescape(value)
                        forms.add(html_decoded)
                    except Exception:
                        pass

                return forms

            # Iterative multi-pass: keep decoding until fixpoint (max 3 passes)
            frontier = set(canonical_forms)
            for _pass in range(3):
                new_forms = set()
                for form in frontier:
                    decoded = _decode_one_pass(form)
                    new_forms.update(decoded - canonical_forms)
                if not new_forms:
                    break
                canonical_forms.update(new_forms)
                frontier = new_forms

            # Unicode confusable mapping: replace common look-alike chars
            _CONFUSABLE_MAP = {
                "\u0435": "e",  # Cyrillic е → Latin e
                "\u0430": "a",  # Cyrillic а → Latin a
                "\u043e": "o",  # Cyrillic о → Latin o
                "\u0440": "p",  # Cyrillic р → Latin p
                "\u0441": "c",  # Cyrillic с → Latin c
                "\u0443": "y",  # Cyrillic у → Latin y
                "\u0445": "x",  # Cyrillic х → Latin x
                "\u0456": "i",  # Cyrillic і → Latin i
                "\u0455": "s",  # Cyrillic ѕ → Latin s
                "\u0458": "j",  # Cyrillic ј → Latin j
                "\uff44": "d",
                "\uff45": "e",
                "\uff4c": "l",  # fullwidth
                "\uff54": "t",
                "\uff52": "r",
                "\uff4f": "o",
                "\uff42": "b",
                "\uff53": "s",
                "\uff48": "h",
            }
            confusable_forms = set()
            for form in canonical_forms:
                mapped = "".join(_CONFUSABLE_MAP.get(c, c) for c in form)
                if mapped != form:
                    confusable_forms.add(mapped)
            canonical_forms.update(confusable_forms)

            # ── Phase 2: Check all canonical forms ────────────────────────
            for form in canonical_forms:
                form_lower = form.lower()

                # Dangerous action keywords
                if any(word in form_lower for word in DANGEROUS_ACTIONS):
                    if form != arg_value:
                        return f"Encoded dangerous command in {arg_name} (decoded: {form[:60]})"
                    # Original text with dangerous keyword is handled by provenance/policy

                # Dangerous / sensitive paths
                if any(path in form_lower for path in DANGEROUS_PATHS):
                    return f"Sensitive path detected in {arg_name}"

            # ── Phase 3: Structural checks (on original value) ────────────
            # Path traversal
            if ".." in arg_value:
                return f"Path traversal in {arg_name}"

            # Shell metacharacters
            if any(char in arg_value for char in ["|", ";", "&", "$(", "`"]):
                return f"Shell metacharacters in {arg_name}"

            # Abnormal length
            if len(arg_value) > 200:
                return f"Abnormally long argument {arg_name} ({len(arg_value)} chars)"

        return None

    def _looks_like_base64(self, s: str) -> bool:
        """Check if string looks like base64 encoding."""
        import re

        # Relaxed check: base64 chars with optional padding, length >= 4
        if not re.match(r"^[A-Za-z0-9+/\n\r]+={0,3}$", s.strip()):
            return False
        stripped = s.strip().replace("\n", "").replace("\r", "")
        return len(stripped) >= 4

    def get_statistics(self) -> Dict[str, Any]:
        """Get enforcement statistics."""
        return {
            **self.stats,
            "provenance_stats": self.provenance.get_statistics(),
            "confirmation_rate": (
                self.stats["confirmed"] / self.stats["total_calls"]
                if self.stats["total_calls"] > 0
                else 0
            ),
            "denial_rate": (
                self.stats["denied"] / self.stats["total_calls"]
                if self.stats["total_calls"] > 0
                else 0
            ),
        }

    def export_logs(self, filepath: str):
        """Export all call logs to JSON file."""
        with open(filepath, "w") as f:
            logs = [log.to_dict() for log in self.call_logs]
            json.dump(logs, f, indent=2)

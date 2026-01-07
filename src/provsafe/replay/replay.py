"""Deterministic replay of evaluation runs."""

import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from ..bench import BenchmarkSuite
from ..proxy import ToolCallProxy, ToolCallRequest
from ..eval import EvaluationMetrics


class ReplayRunner:
    """
    Replays a recorded evaluation run for determinism verification.
    
    Ensures that given the same policy, suite, and seed, we get
    identical decisions and outcomes.
    """
    
    def __init__(self, transcript_path: str):
        self.transcript_path = Path(transcript_path)
        self.transcript = self._load_transcript()
        self.manifest = self._load_manifest()
    
    def _load_transcript(self) -> List[Dict[str, Any]]:
        """Load transcript from JSON file."""
        with open(self.transcript_path, 'r') as f:
            return json.load(f)
    
    def _load_manifest(self) -> Dict[str, Any]:
        """Load manifest from same directory."""
        manifest_path = self.transcript_path.parent / "manifest.json"
        if manifest_path.exists():
            with open(manifest_path, 'r') as f:
                return json.load(f)
        return {}
    
    def verify_determinism(
        self,
        proxy: ToolCallProxy,
        suite: BenchmarkSuite,
        seed: int
    ) -> Dict[str, Any]:
        """
        Verify that replay produces identical results.
        
        Args:
            proxy: Configured proxy with same policy
            suite: Same benchmark suite
            seed: Same random seed
            
        Returns:
            Verification report with discrepancies
        """
        print("\n=== Determinism Verification ===")
        
        # Verify manifest matches
        suite_hash = self._compute_suite_hash(suite)
        if self.manifest.get("suite_hash") != suite_hash:
            print("⚠ Warning: Suite hash mismatch")
        
        if self.manifest.get("seed") != seed:
            print(f"⚠ Warning: Seed mismatch (recorded: {self.manifest.get('seed')}, current: {seed})")
        
        # Replay each task
        discrepancies = []
        total_tasks = len(self.transcript)
        matching = 0
        
        for i, recorded_task in enumerate(self.transcript, 1):
            task_id = recorded_task["task_id"]
            
            # Find corresponding task in suite
            task = next((t for t in suite.tasks if t.id == task_id), None)
            if not task:
                discrepancies.append({
                    "task_id": task_id,
                    "error": "Task not found in suite"
                })
                continue
            
            # Replay decisions
            task_match = self._verify_task(proxy, task, recorded_task)
            if task_match["matches"]:
                matching += 1
            else:
                discrepancies.append(task_match)
            
            print(f"[{i}/{total_tasks}] {task_id}: {'✓' if task_match['matches'] else '✗'}")
        
        match_rate = matching / total_tasks if total_tasks > 0 else 0
        
        print(f"\nMatch Rate: {match_rate:.1%} ({matching}/{total_tasks})")
        
        if match_rate == 1.0:
            print("✓ Perfect determinism - all decisions match!")
        else:
            print(f"✗ Found {len(discrepancies)} discrepancies")
        
        return {
            "total_tasks": total_tasks,
            "matching": matching,
            "match_rate": match_rate,
            "discrepancies": discrepancies,
            "manifest": self.manifest,
        }
    
    def _verify_task(
        self,
        proxy: ToolCallProxy,
        task,
        recorded_task: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verify a single task's decisions match."""
        recorded_decisions = recorded_task.get("decisions", [])
        
        mismatches = []
        
        for i, call_spec in enumerate(task.tool_calls):
            if i >= len(recorded_decisions):
                mismatches.append({
                    "call_index": i,
                    "error": "Recorded decision not found"
                })
                continue
            
            recorded = recorded_decisions[i]
            
            # Replay the decision
            request = ToolCallRequest(
                tool=call_spec.tool,
                action=call_spec.action,
                resource=call_spec.resource,
                args=call_spec.args,
                context={"task_id": task.id}
            )
            
            decision = proxy.enforce_policy(request, user_context={"user_id": "test_user"})
            
            # Compare outcomes
            if decision.outcome.value != recorded["outcome"]:
                mismatches.append({
                    "call_index": i,
                    "tool": call_spec.tool,
                    "action": call_spec.action,
                    "expected_outcome": recorded["outcome"],
                    "actual_outcome": decision.outcome.value,
                    "expected_reason": recorded["reason_code"],
                    "actual_reason": decision.reason_code.value,
                })
        
        return {
            "task_id": task.id,
            "matches": len(mismatches) == 0,
            "mismatches": mismatches
        }
    
    def _compute_suite_hash(self, suite: BenchmarkSuite) -> str:
        """Compute hash of benchmark suite."""
        suite_json = json.dumps(suite.model_dump(), sort_keys=True)
        return hashlib.sha256(suite_json.encode()).hexdigest()[:16]
    
    def get_metrics_diff(self, new_metrics: EvaluationMetrics) -> Dict[str, Any]:
        """
        Compare new metrics against recorded metrics.
        
        Args:
            new_metrics: Newly computed metrics
            
        Returns:
            Dictionary of metric differences
        """
        recorded_metrics = self.manifest.get("metrics", {})
        
        diff = {}
        for key in ["tsr", "uar", "asr", "confirmations_per_task", "avg_latency_ms"]:
            recorded = recorded_metrics.get(key, 0)
            new = getattr(new_metrics, key, 0)
            
            if abs(recorded - new) > 0.001:  # Allow small floating point errors
                diff[key] = {
                    "recorded": recorded,
                    "new": new,
                    "delta": new - recorded
                }
        
        return diff

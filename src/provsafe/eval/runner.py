"""Evaluation runner for benchmark suites."""

import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..bench import BenchmarkSuite, BenchmarkTask, ExpectedOutcome, TaskType
from ..proxy import ToolCallProxy, ToolCallRequest, DecisionOutcome
from ..provenance import ProvenanceTracker, TrustLabel
from .metrics import TaskResult, EvaluationMetrics


class EvaluationRunner:
    """
    Runs benchmark suites and computes metrics.

    Executes tasks, enforces policy via proxy, tracks provenance,
    and generates evaluation reports.
    """

    def __init__(
        self,
        proxy: ToolCallProxy,
        mock_tools,
        provenance_tracker: Optional[ProvenanceTracker] = None,
        output_dir: Optional[str] = None,
        seed: Optional[int] = None,
    ):
        self.proxy = proxy
        self.mock_tools = mock_tools
        self.provenance_tracker = provenance_tracker or ProvenanceTracker()
        self.output_dir = Path(output_dir) if output_dir else Path("runs/default")
        self.seed = seed

        self.results: List[TaskResult] = []
        self.transcript: List[Dict[str, Any]] = []

    def run_task(self, task: BenchmarkTask) -> TaskResult:
        """
        Run a single benchmark task.

        Args:
            task: Benchmark task to run

        Returns:
            TaskResult with outcome
        """
        start_time = time.time()

        # Add input to provenance
        trust_label = (
            TrustLabel.TRUSTED if task.task_type == TaskType.BENIGN else TrustLabel.UNTRUSTED
        )
        input_node_id = self.provenance_tracker.add_input(
            content={"user_input": task.user_input},
            trust_label=trust_label,
            metadata={"task_id": task.id},
        )

        tool_calls_made = 0
        confirmations_required = 0
        attack_succeeded = False
        task_success = True
        decisions = []

        # Execute each tool call in the task
        for call_spec in task.tool_calls:
            # Create request
            request = ToolCallRequest(
                tool=call_spec.tool,
                action=call_spec.action,
                resource=call_spec.resource,
                args=call_spec.args,
                context={
                    "task_id": task.id,
                    "provenance": self.provenance_tracker.get_provenance_summary(input_node_id),
                },
            )

            # Enforce policy
            decision = self.proxy.enforce_policy(request, user_context={"user_id": "test_user"})

            tool_calls_made += 1
            decisions.append(
                {
                    "tool": call_spec.tool,
                    "action": call_spec.action,
                    "resource": call_spec.resource,
                    "outcome": decision.outcome.value,
                    "reason_code": decision.reason_code.value,
                    "expected": call_spec.expected_outcome.value,
                }
            )

            # Track confirmations
            if decision.outcome == DecisionOutcome.CONFIRM:
                confirmations_required += 1

            # Check if outcome matches expectation
            expected_match = (
                (
                    decision.outcome == DecisionOutcome.ALLOW
                    and call_spec.expected_outcome == ExpectedOutcome.ALLOW
                )
                or (
                    decision.outcome == DecisionOutcome.DENY
                    and call_spec.expected_outcome == ExpectedOutcome.DENY
                )
                or (
                    decision.outcome == DecisionOutcome.CONFIRM
                    and call_spec.expected_outcome == ExpectedOutcome.CONFIRM
                )
            )

            if not expected_match:
                task_success = False

            # For attacks: check if this was the goal and it was allowed
            if task.task_type == TaskType.ATTACK and call_spec.is_attack_goal:
                if decision.outcome == DecisionOutcome.ALLOW:
                    attack_succeeded = True

            # Log in provenance
            tool_call_node = self.provenance_tracker.log_tool_call(
                request=request,
                decision=decision,
                timestamp=datetime.now(),
                parent_ids=[input_node_id],
            )

            # Execute if allowed
            if decision.outcome == DecisionOutcome.ALLOW:
                result = self.mock_tools.execute(
                    call_spec.tool, call_spec.action, call_spec.resource, call_spec.args
                )
                # Log effect
                self.provenance_tracker.add_effect(
                    content={"result": result},
                    tool_call_id=tool_call_node,
                    metadata={"success": result.get("success", False)},
                )

        latency_ms = (time.time() - start_time) * 1000

        result = TaskResult(
            task_id=task.id,
            task_name=task.name,
            task_type=task.task_type.value,
            success=task_success,
            tool_calls_made=tool_calls_made,
            confirmations_required=confirmations_required,
            attack_succeeded=attack_succeeded,
            latency_ms=latency_ms,
            details={"decisions": decisions},
        )

        # Add to transcript
        self.transcript.append(
            {
                "task_id": task.id,
                "task_name": task.name,
                "task_type": task.task_type.value,
                "timestamp": datetime.now().isoformat(),
                "result": {
                    "success": result.success,
                    "tool_calls": tool_calls_made,
                    "confirmations": confirmations_required,
                    "attack_succeeded": attack_succeeded,
                },
                "decisions": decisions,
            }
        )

        return result

    def run_suite(self, suite: BenchmarkSuite) -> EvaluationMetrics:
        """
        Run entire benchmark suite.

        Args:
            suite: Benchmark suite to run

        Returns:
            Aggregated evaluation metrics
        """
        print(f"\nRunning benchmark suite: {suite.name}")
        print(f"Tasks: {len(suite.tasks)}")

        self.results = []
        self.transcript = []

        for i, task in enumerate(suite.tasks, 1):
            print(f"[{i}/{len(suite.tasks)}] Running: {task.name}...", end=" ")
            result = self.run_task(task)
            self.results.append(result)
            print("✓" if result.success else "✗")

        metrics = EvaluationMetrics.from_results(self.results)

        # Save results
        self._save_results(suite, metrics)

        return metrics

    def _save_results(self, suite: BenchmarkSuite, metrics: EvaluationMetrics):
        """Save evaluation results to output directory."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Save metrics
        metrics_path = self.output_dir / "metrics.json"
        with open(metrics_path, "w") as f:
            json.dump(metrics.to_dict(), f, indent=2)

        # Save transcript
        transcript_path = self.output_dir / "transcript.json"
        with open(transcript_path, "w") as f:
            json.dump(self.transcript, f, indent=2, default=str)

        # Save provenance graph
        provenance_path = self.output_dir / "provenance.json"
        self.provenance_tracker.save_to_file(str(provenance_path))

        # Save manifest with hashes
        manifest = self._create_manifest(suite, metrics)
        manifest_path = self.output_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        print(f"\nResults saved to: {self.output_dir}")

    def _create_manifest(self, suite: BenchmarkSuite, metrics: EvaluationMetrics) -> Dict[str, Any]:
        """Create manifest with hashes for determinism verification."""

        # Compute policy hash (would use actual policy file)
        policy_hash = hashlib.sha256(b"policy_placeholder").hexdigest()[:16]

        # Compute suite hash
        suite_json = json.dumps(suite.model_dump(), sort_keys=True)
        suite_hash = hashlib.sha256(suite_json.encode()).hexdigest()[:16]

        return {
            "timestamp": datetime.now().isoformat(),
            "suite_name": suite.name,
            "suite_version": suite.version,
            "suite_hash": suite_hash,
            "policy_hash": policy_hash,
            "seed": self.seed,
            "metrics": metrics.to_dict(),
            "task_count": len(suite.tasks),
        }

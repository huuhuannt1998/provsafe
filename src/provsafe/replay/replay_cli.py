"""CLI entry point for replaying evaluation runs."""

import argparse
import sys

from provsafe.bench import BenchmarkSuite, MockToolRegistry
from provsafe.proxy import ToolRegistry, ToolCallProxy
from provsafe.policy import CapabilityPolicy, PolicyEngine
from provsafe.replay import ReplayRunner
from provsafe.eval.run_suite import setup_tool_schemas


def main():
    parser = argparse.ArgumentParser(
        description="Replay PROVSAFE evaluation run for determinism verification"
    )
    parser.add_argument(
        "--transcript",
        required=True,
        help="Path to transcript.json from previous run"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify determinism by replaying decisions"
    )
    
    args = parser.parse_args()
    
    # Load replay runner
    print(f"Loading transcript: {args.transcript}")
    replay = ReplayRunner(args.transcript)
    
    print(f"\nManifest Info:")
    print(f"  Suite: {replay.manifest.get('suite_name')}")
    print(f"  Version: {replay.manifest.get('suite_version')}")
    print(f"  Seed: {replay.manifest.get('seed')}")
    print(f"  Tasks: {replay.manifest.get('task_count')}")
    
    if replay.manifest.get('metrics'):
        print(f"\nRecorded Metrics:")
        metrics = replay.manifest['metrics']
        print(f"  TSR: {metrics.get('tsr', 0):.2%}")
        print(f"  UAR: {metrics.get('uar', 0):.2%}")
        print(f"  ASR: {metrics.get('asr', 0):.2%}")
        print(f"  Confirmations/Task: {metrics.get('confirmations_per_task', 0):.2f}")
    
    if args.verify:
        # Need to reconstruct the original setup
        print("\n⚠ Full verification requires --suite and --policy arguments")
        print("For now, showing transcript summary...")
        
        print(f"\nTranscript contains {len(replay.transcript)} tasks")
        for task in replay.transcript[:5]:  # Show first 5
            print(f"  - {task['task_id']}: {task['task_name']} ({task['task_type']})")
        if len(replay.transcript) > 5:
            print(f"  ... and {len(replay.transcript) - 5} more")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

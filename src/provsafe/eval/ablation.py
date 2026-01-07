"""Ablation study framework for component analysis."""

from typing import Dict, Any, List
from dataclasses import dataclass
import json
from pathlib import Path

from ..bench import BenchmarkSuite, MockToolRegistry
from ..proxy import ToolRegistry, ToolCallProxy
from ..policy import PolicyEngine, CapabilityPolicy
from ..provenance import ProvenanceTracker
from .runner import EvaluationRunner
from .metrics import EvaluationMetrics


@dataclass
class AblationConfig:
    """Configuration for an ablation experiment."""
    name: str
    description: str
    enable_rate_limiting: bool = True
    enable_time_constraints: bool = True
    enable_provenance: bool = True
    enable_evidence_requirements: bool = True
    enable_confirmations: bool = True


class AblationStudy:
    """
    Runs ablation studies to measure contribution of each component.
    
    Systematically disables features to understand their impact on
    security and usability metrics.
    """
    
    def __init__(
        self,
        suite: BenchmarkSuite,
        tool_registry: ToolRegistry,
        base_policy_path: str,
        seed: int = 42,
        output_dir: str = "runs/ablation"
    ):
        self.suite = suite
        self.tool_registry = tool_registry
        self.base_policy_path = base_policy_path
        self.seed = seed
        self.output_dir = output_dir
        self.results: List[Dict[str, Any]] = []
    
    def _create_ablated_policy(
        self,
        base_policy: CapabilityPolicy,
        config: AblationConfig
    ) -> CapabilityPolicy:
        """Create policy with specific features disabled."""
        import copy
        
        policy = copy.deepcopy(base_policy)
        policy.name = f"Ablation: {config.name}"
        
        # Disable features as specified
        if not config.enable_rate_limiting:
            policy.global_rate_limit = None
            for rule in policy.rules:
                rule.rate_limit = None
        
        if not config.enable_time_constraints:
            for rule in policy.rules:
                rule.time_constraints = []
        
        if not config.enable_evidence_requirements:
            for rule in policy.rules:
                rule.evidence_requirements = None
        
        if not config.enable_confirmations:
            for rule in policy.rules:
                rule.require_confirmation = False
        
        return policy
    
    def run_ablation(self, config: AblationConfig) -> Dict[str, Any]:
        """Run evaluation with specific ablation configuration."""
        print(f"\nRunning ablation: {config.name}")
        print(f"  {config.description}")
        
        # Load and modify policy
        base_policy = CapabilityPolicy.from_yaml(self.base_policy_path)
        policy = self._create_ablated_policy(base_policy, config)
        
        # Setup components
        policy_engine = PolicyEngine(policy)
        
        provenance_tracker = ProvenanceTracker() if config.enable_provenance else None
        
        proxy = ToolCallProxy(
            tool_registry=self.tool_registry,
            policy_engine=policy_engine,
            provenance_tracker=provenance_tracker
        )
        
        mock_tools = MockToolRegistry(seed=self.seed)
        
        # Run evaluation
        output_subdir = f"{self.output_dir}/{config.name.lower().replace(' ', '_')}"
        runner = EvaluationRunner(
            proxy=proxy,
            mock_tools=mock_tools,
            provenance_tracker=provenance_tracker,
            output_dir=output_subdir,
            seed=self.seed
        )
        
        metrics = runner.run_suite(self.suite)
        
        result = {
            "config": config,
            "metrics": metrics.to_dict(),
            "output_dir": output_subdir
        }
        
        self.results.append(result)
        return result
    
    def run_full_ablation_study(self) -> List[Dict[str, Any]]:
        """Run complete ablation study with all configurations."""
        print("\n=== Ablation Study ===")
        
        configs = [
            AblationConfig(
                name="Full System",
                description="All features enabled",
                enable_rate_limiting=True,
                enable_time_constraints=True,
                enable_provenance=True,
                enable_evidence_requirements=True,
                enable_confirmations=True
            ),
            AblationConfig(
                name="No Provenance",
                description="Disable provenance tracking",
                enable_provenance=False
            ),
            AblationConfig(
                name="No Rate Limiting",
                description="Disable rate limiting",
                enable_rate_limiting=False
            ),
            AblationConfig(
                name="No Time Constraints",
                description="Disable time-of-day constraints",
                enable_time_constraints=False
            ),
            AblationConfig(
                name="No Evidence Requirements",
                description="Disable evidence requirements",
                enable_evidence_requirements=False
            ),
            AblationConfig(
                name="No Confirmations",
                description="Disable user confirmations",
                enable_confirmations=False
            ),
            AblationConfig(
                name="Minimal System",
                description="Only basic policy rules",
                enable_rate_limiting=False,
                enable_time_constraints=False,
                enable_provenance=False,
                enable_evidence_requirements=False,
                enable_confirmations=False
            ),
        ]
        
        for config in configs:
            self.run_ablation(config)
        
        # Save results
        self._save_results()
        
        return self.results
    
    def _save_results(self):
        """Save ablation study results."""
        output_path = Path(self.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Convert to serializable format
        serializable_results = []
        for result in self.results:
            serializable_results.append({
                "name": result["config"].name,
                "description": result["config"].description,
                "features": {
                    "rate_limiting": result["config"].enable_rate_limiting,
                    "time_constraints": result["config"].enable_time_constraints,
                    "provenance": result["config"].enable_provenance,
                    "evidence_requirements": result["config"].enable_evidence_requirements,
                    "confirmations": result["config"].enable_confirmations,
                },
                "metrics": result["metrics"]
            })
        
        with open(output_path / "ablation_results.json", 'w') as f:
            json.dump(serializable_results, f, indent=2)
    
    def print_ablation_analysis(self):
        """Print analysis of ablation study results."""
        if not self.results:
            print("No ablation results to analyze")
            return
        
        print("\n" + "=" * 120)
        print("ABLATION STUDY ANALYSIS")
        print("=" * 120)
        
        print(f"\n{'Configuration':<20} {'Prov':>5} {'Rate':>5} {'Time':>5} {'Evid':>5} {'Conf':>5} "
              f"{'TSR':>8} {'UAR':>8} {'ASR':>8}")
        print("-" * 120)
        
        for result in self.results:
            config = result["config"]
            metrics = result["metrics"]
            
            prov = "✓" if config.enable_provenance else "✗"
            rate = "✓" if config.enable_rate_limiting else "✗"
            time = "✓" if config.enable_time_constraints else "✗"
            evid = "✓" if config.enable_evidence_requirements else "✗"
            conf = "✓" if config.enable_confirmations else "✗"
            
            print(f"{config.name:<20} {prov:>5} {rate:>5} {time:>5} {evid:>5} {conf:>5} "
                  f"{metrics['tsr']:>7.1%} {metrics['uar']:>7.1%} {metrics['asr']:>7.1%}")
        
        print("-" * 120)
        
        # Calculate feature contributions
        full_system = next(r for r in self.results if r["config"].name == "Full System")
        full_asr = full_system["metrics"]["asr"]
        
        print("\n=== Feature Contribution to Security (ASR Reduction) ===")
        
        feature_impacts = []
        for result in self.results:
            if result["config"].name != "Full System":
                asr_delta = result["metrics"]["asr"] - full_asr
                if asr_delta > 0:  # Feature helps security
                    feature_name = result["config"].name.replace("No ", "")
                    feature_impacts.append((feature_name, asr_delta))
        
        feature_impacts.sort(key=lambda x: x[1], reverse=True)
        
        for feature, impact in feature_impacts:
            print(f"  {feature:<25} +{impact:>6.1%} ASR when disabled")
        
        print("=" * 120 + "\n")

from dataclasses import dataclass

from models.stage_metric import StageMetrics


@dataclass
class ExperimentResult:
    """Complete result for one experiment run."""

    variant: str
    attack_id: int
    top_feature: str
    stages: list[StageMetrics]
    # final_explanation: dict[str, any]
    total_latency: float
    # context_nodes: list[str]

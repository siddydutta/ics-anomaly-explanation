from dataclasses import dataclass
from enum import Enum

from .stage import StageMetrics


class ExperimentVariant(Enum):
    BASELINE = "BASELINE"  # Naive RAG: No metadata filtering
    NO_MITRE = "NO_MITRE"  # Complex RAG: Only SWaT metadata filtering
    FULL = "FULL"  # Advanced RAG: SWaT metadata filtering + MITRE ATT&CK metadata inference


@dataclass
class ExperimentResult:
    """Complete result for one experiment run."""

    variant: str
    attack_id: int
    top_feature: str
    stages: list[StageMetrics]
    # explanation: dict[str, any]
    total_latency: float
    context_nodes: list[str]

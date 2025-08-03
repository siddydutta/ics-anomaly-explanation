from dataclasses import dataclass


@dataclass
class StageMetrics:
    """Metrics for a single pipeline stage."""

    stage_name: str
    latency_seconds: float
    embedding_tokens: int
    input_tokens: int
    output_tokens: int
    retrieved_docs: int = 0

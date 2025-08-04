from pydantic import BaseModel, Field


class ExplanationOutput(BaseModel):
    """Output for final anomaly explanation."""

    explanation: str = Field(..., description="Comprehensive anomaly explanation")
    possible_cause: str = Field(
        ..., description="Potential root causes of this anomaly"
    )
    potential_impact: str = Field(
        ..., description="Possible implications for this anomaly"
    )
    mitigation_strategy: str = Field(..., description="Recommended mitigation actions")

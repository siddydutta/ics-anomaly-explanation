from pydantic import BaseModel, Field


class ExplanationOutput(BaseModel):
    """Output for final concise anomaly explanation."""

    explanation: str = Field(
        ...,
        description="Brief explanation of what happened based on statistical evidence (2-3 sentences)",
    )
    possible_cause: str = Field(
        ...,
        description="Most likely root causes matching this statistical pattern (2-3 sentences)",
    )
    potential_impact: str = Field(
        ...,
        description="Specific impacts based on this component and statistical evidence (2-3 sentences)",
    )
    mitigation_strategy: str = Field(
        ..., description="Targeted mitigation for this anomaly pattern (2-3 sentences)"
    )

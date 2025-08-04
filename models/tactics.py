from pydantic import BaseModel, Field


class TacticsOutput(BaseModel):
    """Output for MITRE ATT&CK tactics inference."""

    tactics: list[str] = Field(
        ..., description="Relevant ICS MITRE ATT&CK tactics (max 3)"
    )
    reasoning: str = Field(
        ..., description="Brief explanation of why these tactics are relevant"
    )

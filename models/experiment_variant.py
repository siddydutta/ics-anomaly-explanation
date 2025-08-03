from enum import Enum


class ExperimentVariant(Enum):
    BASELINE = "BASELINE"  # Naive RAG: No metadata filtering
    NO_MITRE = "NO_MITRE"  # Complex RAG: Only SWaT metadata filtering
    FULL = "FULL"  # Advanced RAG: SWaT metadata filtering + MITRE ATT&CK metadata inference

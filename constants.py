from models import ExperimentVariant

VARIANT_MAP = {
    "BASELINE": ExperimentVariant.BASELINE,
    "NO_MITRE": ExperimentVariant.NO_MITRE,
    "FULL": ExperimentVariant.FULL,
}

MITRE_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Evasion",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Inhibit Response Function",
    "Impair Process Control",
    "Impact",
]

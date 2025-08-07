from models import ExperimentVariant

MITRE_FILTER_INFERENCE = """
An anomaly was detected with component: {top_feature}

Context about the anomalous component:
{context}        

Available MITRE ATT&CK ICS tactics: {MITRE_TACTICS}

Task: Identify the 3 most relevant tactics that could be associated with this component anomaly.

Consider:
- The component's specific function in the SWaT testbed
- Potential attack vectors targeting this component type
- Common ICS vulnerabilities for similar components

Your selections will be used to retrieve specific ICS attack techniques for anomaly explanation.
"""

BASELINE_EXPLANATION_PROMPT = """
You are an expert in industrial control systems security.

An anomaly was detected in component: {top_feature}

*************
Statistical evidence:
{anomaly_stats}

Context:
{context}
*************

Provide a concise, data-driven analysis. Keep each response field to 2-3 sentences maximum. Focus on specifics based on the statistical evidence rather than generic possibilities.

Analyse:
- What the statistical pattern indicates physically happened
- Root causes that would create this exact statistical signature
- Specific impacts based on this component's role and the statistical evidence
- Targeted mitigation for this particular anomaly pattern

Reference MITRE ATT&CK for ICS techniques where applicable for cyber threats.
"""

FULL_EXPLANATION_PROMPT = """
You are an expert in industrial control systems security.

An anomaly was detected in component: {top_feature}

*************
Statistical evidence:
{anomaly_stats}

Context:
{context}
*************

Provide a concise, data-driven analysis. Keep each response field to 2-3 sentences maximum. Focus on specifics based on the statistical evidence rather than generic possibilities.

Analyse:
- What the statistical pattern indicates physically happened
- Root causes that would create this exact statistical signature  
- Specific impacts based on this component's role and the statistical evidence
- Targeted mitigation for this particular anomaly pattern

Base analysis strictly on provided context. Reference specific MITRE ATT&CK techniques from the context for cyber threats.
"""

EXPLANATION_PROMPT_MAP = {
    ExperimentVariant.BASELINE: BASELINE_EXPLANATION_PROMPT,
    ExperimentVariant.NO_MITRE: BASELINE_EXPLANATION_PROMPT,  # same prompt, since no MITRE context
    ExperimentVariant.FULL: FULL_EXPLANATION_PROMPT,
}

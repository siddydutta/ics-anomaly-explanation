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

EXPLANATION_PROMPT = """
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
- The component function and what the statistical pattern indicates physically happened
- Root causes that would create this exact statistical signature based on MITRE ATT&CK framework
- Specific impacts based on this component's role in the stage and the statistical evidence
- Targeted mitigation for this particular anomaly pattern based on MITRE ATT&CK framework

Base analysis strictly on provided context. Reference specific MITRE ATT&CK techniques, causes, mitigations where applicable.
"""

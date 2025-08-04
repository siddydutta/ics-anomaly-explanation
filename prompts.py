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

Context about the component from SWaT documentation:
{context}

Please provide a comprehensive explanation of this anomaly including:
1. Component function and role in the SWaT water treatment system phase
2. Possible causes (operational failures and potential cyber threats)
3. Potential impacts if unaddressed (stage-level and system-wide risks)
4. Recommended mitigation strategies (technical and operational measures)

Focus on specifics rather than generalities. Analyze:
- How this component's anomaly would specifically impact its directly connected components
- The unique attack surface and vulnerabilities of this particular component
- Specific failure modes and their downstream consequences in the SWaT process

Base your analysis on the provided SWaT system context. Additionally, leverage your knowledge to reference specific MITRE ATT&CK for ICS framework techniques to identify potential cyber attack causes and security mitigations.
"""

FULL_EXPLANATION_PROMPT = """
You are an expert in industrial control systems security.

An anomaly was detected in component: {top_feature}

Context about the component from SWaT documentation:
{context}

Please provide a comprehensive explanation of this anomaly including:
1. Component function and role in the SWaT water treatment system phase
2. Possible causes (operational failures and potential cyber threats)
3. Potential impacts if unaddressed (stage-level and system-wide risks)
4. Recommended mitigation strategies (technical and operational measures)

Focus on specifics rather than generalities. Analyze:
- How this component's anomaly would specifically impact its directly connected components
- The unique attack surface and vulnerabilities of this particular component
- Specific failure modes and their downstream consequences in the SWaT process

Base your analysis strictly on the provided context. Use the SWaT system documentation for impact analysis and reference specific MITRE ATT&CK techniques for identifying potential cyber attack causes and security mitigations.
"""

EXPLANATION_PROMPT_MAP = {
    ExperimentVariant.BASELINE: BASELINE_EXPLANATION_PROMPT,
    ExperimentVariant.NO_MITRE: BASELINE_EXPLANATION_PROMPT,  # same prompt, since no MITRE context
    ExperimentVariant.FULL: FULL_EXPLANATION_PROMPT,
}

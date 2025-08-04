from models import ExperimentVariant

MITRE_FILTER_INFERENCE = """
An anomaly was detected with component: {top_feature}

Context about the anomalous component:
{context}        

Available MITRE ATT&CK ICS tactics: {MITRE_TACTICS}
        
Based on the component information and its role in the SWaT testbed process,
identify at most 3 most relevant tactics that could be associated with an anomaly
in this component. Consider both the component's function and potential
attack vectors.
"""

BASELINE_EXPLANATION_PROMPT = """
An anomaly was detected in component: {top_feature}

Provide a comprehensive explanation of this anomaly including:
1. What this component does and its role in the system
2. Possible causes of the anomaly
3. Potential impacts if not addressed
4. Recommended mitigation strategies
"""

NO_MITRE_EXPLANATION_PROMPT = """
An anomaly was detected in component: {top_feature}
            
Context about the component:
{context}

Provide a comprehensive explanation of this anomaly including:
1. What this component does and its role in the system
2. Possible causes of the anomaly
3. Potential impacts if not addressed
4. Recommended mitigation strategies

Use your knowledge of the MITRE ATT&CK for ICS framework to inform causes, impacts and mitigation strategies.
"""


FULL_EXPLANATION_PROMPT = """
An anomaly was detected in component: {top_feature}

Context about the component and relevant MITRE ATT&CK techniques:
{context}

Provide a comprehensive explanation of this anomaly including:
1. What this component does and its role in the system
2. Possible causes of the anomaly
3. Potential impacts if not addressed
4. Recommended mitigation strategies

Use only knowledge from the provided context.
"""


EXPLANATION_PROMPT_MAP = {
    ExperimentVariant.BASELINE: BASELINE_EXPLANATION_PROMPT,
    ExperimentVariant.NO_MITRE: NO_MITRE_EXPLANATION_PROMPT,
    ExperimentVariant.FULL: FULL_EXPLANATION_PROMPT,
}

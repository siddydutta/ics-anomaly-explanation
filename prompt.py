from models import ExperimentVariant

MITRE_FILTER_INFERENCE = """
An anomaly was detected with component: {top_feature}

Context about the anomalous component:
{context}        

Available MITRE ATT&CK ICS tactics: {MITRE_TACTICS}
        
Based on the component information and its role in the SWaT testbed process,
identify at most 3 most relevant tactics that could be associated with an anomaly
in this component. Consider both the component's function and potential
attack vectors that could target this type of industrial control system component.

Your selected tactics will be used to retrieve specific ICS attack techniques 
that will help explain the anomaly's potential security implications.
"""

BASELINE_EXPLANATION_PROMPT = """
An anomaly was detected in component: {top_feature}

Provide a comprehensive explanation of this anomaly including:
1. What this component does and its role in the SWaT water treatment system
2. Possible operational causes of the anomaly (sensor drift, mechanical failure, etc.)
3. Potential impacts on the water treatment process if not addressed
4. Recommended operational mitigation strategies

Focus on operational and engineering aspects of the anomaly.
"""

NO_MITRE_EXPLANATION_PROMPT = """
An anomaly was detected in component: {top_feature}
            
Context about the component from SWaT documentation:
{context}

Provide a comprehensive explanation of this anomaly including:
1. What this component does and its role in the SWaT water treatment system
2. Possible causes of the anomaly (both operational failures and potential cyber threats)
3. Potential impacts if not addressed (operational disruption and security risks)
4. Recommended mitigation strategies (technical, operational, and security measures)

Draw upon your knowledge of industrial control systems security and the MITRE ATT&CK 
for ICS framework to identify potential cyber attack scenarios, but prioritize 
insights that can be derived from the provided SWaT system documentation.
"""

FULL_EXPLANATION_PROMPT = """
An anomaly was detected in component: {top_feature}

Context includes SWaT system documentation and relevant MITRE ATT&CK ICS techniques:
{context}

Provide a comprehensive explanation of this anomaly including:
1. What this component does and its role in the SWaT water treatment system
2. Possible causes of the anomaly (operational failures and cyber attack techniques from context)
3. Potential impacts if not addressed (operational and security consequences)
4. Recommended mitigation strategies (addressing both operational and security aspects)

Base your analysis strictly on the provided context. When discussing potential attack 
scenarios, reference the specific MITRE ATT&CK techniques provided. For operational 
aspects, use the SWaT system documentation.
"""

EXPLANATION_PROMPT_MAP = {
    ExperimentVariant.BASELINE: BASELINE_EXPLANATION_PROMPT,
    ExperimentVariant.NO_MITRE: NO_MITRE_EXPLANATION_PROMPT,
    ExperimentVariant.FULL: FULL_EXPLANATION_PROMPT,
}

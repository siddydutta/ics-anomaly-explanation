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

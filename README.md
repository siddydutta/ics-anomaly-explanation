# ICS Anomaly Explanation

## Setup

```shell
git clone https://github.com/siddydutta/ics-anomaly-explanation.git
cd ics-anomaly-explanation
python3.12 -m venv venv/
source venv/bin/activate
pip install -r requirements.txt
cp .env.development .env
```

## Usage

### ICS Anomaly Attributions

Uses the attributoin results from the [ICS Anomaly Attributions](https://github.com/siddydutta/ics-anomaly-attribution) repository to process top-K attributions for each attack.


```shell
python process_attributions.py --threshold 60
```

This gives a **k=5** attributions for each attack in [attributions](data/attributions.json).


### ICS Anomaly Statistics

Uses the detection results from the [ICS Anomaly Attributions](https://github.com/siddydutta/ics-anomaly-attribution) repository to compute various temporal statistics for each attack.

```shell
python process_anomalies.py
```


### ICS Anomaly Explanations

The system supports three distinct approaches for generating explanations for ICS anomalies. Each variant leverages different levels of domain knowledge and metadata filtering:

1. **BASELINE**  
   This variant uses a naive Retrieval-Augmented Generation (RAG) approach. Explanations are generated solely based on the top feature attribution for each attack, without applying any metadata filtering. This serves as a simple baseline for comparison.

2. **NO MITRE**  
   In this variant, explanations are generated using the top feature attribution, but with additional filtering based on SWaT technical metadata. This approach provides more context than the baseline by leveraging domain-specific metadata from the SWaT system.

3. **FULL**  
   The most advanced variant combines both SWaT technical metadata filtering and MITRE ATT&CK metadata inference. Explanations are generated using the top feature attribution, enriched by comprehensive filtering from both sources.

```shell
python main.py --attack 0 --variant BASELINE --output-dir output/
python main.py --attack 0 --variant NO_MITRE --output-dir output/
python main.py --attack 0 --variant FULL --output-dir output/
```

OR

```shell
chmod +x run_explanations.sh
./run_explanations.sh 0
```

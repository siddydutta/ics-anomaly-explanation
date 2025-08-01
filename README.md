# ICS Anomaly Explanation

## Setup

```shell
git clone https://github.com/siddydutta/ics-anomaly-explanation.git
cd ics-anomaly-explanation
python3.12 -m venv venv/
source venv/bin/activate
pip install -r requirements.txt
```

## ICS Anomaly Attributions

Uses the results from the [ICS Anomaly Attributions](https://github.com/siddydutta/ics-anomaly-attribution) repository to process top-K attributions for each attack.


```shell
python process_attributions.py --threshold 60
```

This gives a **k=5** attributions for each attack in [attributions](data/attributions.json).

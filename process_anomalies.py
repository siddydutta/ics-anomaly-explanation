import json
import logging
import os
import pickle
import warnings
from io import BytesIO

import numpy as np
import pandas as pd
import requests
from tqdm import tqdm

warnings.simplefilter(action="ignore", category=UserWarning)


logger = logging.getLogger(__name__)


REPO_BASE_URL = "https://raw.githubusercontent.com/siddydutta/ics-anomaly-attribution/refs/heads/main/"
MODEL_NAME = "LSTM-SWAT-l2-hist50-units64-results"
FILENAME = "all-detection-points.pkl"
DETECTION_POINTS_FILE = f"meta-storage/{MODEL_NAME}-{FILENAME}"
DETECTIONS_DIR = "data/detections/"
SWAT_DATA_FILE = f"data/SWATV0_{{TYPE}}.csv"
ATTRIBUTIONS_FILE = "attributions.json"
OUTPUT_DIR = "output/"


def fetch_detection_points() -> dict:
    """
    Fetch detection points from the remote repository, if it doesn't exist locally.

    Returns:
        dict: A dictionary containing detection points for the specified model.
    """
    url = REPO_BASE_URL + DETECTION_POINTS_FILE
    local_path = os.path.join(DETECTIONS_DIR, f"{MODEL_NAME}-{FILENAME}")
    if os.path.exists(local_path):
        with open(local_path, "rb") as f:
            return pickle.load(f)
    else:
        os.makedirs(DETECTIONS_DIR, exist_ok=True)

    response = requests.get(url)
    if response.status_code == 200:
        detection_points = pickle.load(BytesIO(response.content))
        detection_points = detection_points.get(MODEL_NAME, {})
        with open(local_path, "wb") as f:
            pickle.dump(detection_points, f)
        return detection_points
    else:
        raise Exception(
            f"Failed to fetch detection points from {url}. "
            f"Status code: {response.status_code}"
        )


def retrieve_swat_data(data_type: str) -> pd.DataFrame:
    """
    Retrieve SWAT data from the local storage.

    Args:
        data_type (str): The type of SWAT data to retrieve.

    Returns:
        pd.DataFrame: A DataFrame containing the SWAT data.
    """
    local_path = SWAT_DATA_FILE.format(TYPE=data_type)
    if os.path.exists(local_path):
        dataframe = pd.read_csv(local_path)
        dataframe["Timestamp"] = pd.to_datetime(dataframe["Timestamp"], errors="coerce")
        return dataframe
    else:
        raise FileNotFoundError(f"SWAT data file not found: {local_path}")


def calculate_stats(values: np.ndarray) -> dict:
    """Calculate basic statistics."""
    if len(values) == 0:
        return {"mean": 0, "std": 0, "min": 0, "max": 0, "count": 0}

    return {
        "mean": float(np.mean(values)),
        "std": float(np.std(values)),
        "min": float(np.min(values)),
        "max": float(np.max(values)),
        "count": len(values),
    }


def compute_anomaly_statistics(
    detection_points: np.ndarray,
    test_dataset: pd.DataFrame,
    component_name: str,
) -> dict:
    detection_min = min(detection_points)
    detection_max = max(detection_points)

    # Baseline: Use recent historical data before the detection window
    baseline_end = detection_min - 1
    baseline_start = max(0, baseline_end - (detection_max - detection_min))
    baseline_values = test_dataset.iloc[baseline_start:baseline_end][
        component_name
    ].values

    detected_values = test_dataset.iloc[detection_points][component_name].values

    # Calculate stats
    baseline_stats = calculate_stats(baseline_values)
    detected_stats = calculate_stats(detected_values)
    detected_change_pct = (
        (detected_stats["mean"] - baseline_stats["mean"]) / baseline_stats["mean"] * 100
    )

    return {
        "baseline_stats": baseline_stats,
        "detected_stats": detected_stats,
        "detected_change_percent": f"{detected_change_pct:.2f}%",
    }


def main():
    """
    Main execution function to compute anomaly statistics based on detection points.
    """
    detection_points = fetch_detection_points()
    df_test = retrieve_swat_data("test")
    attributions = json.load(open(os.path.join(OUTPUT_DIR, ATTRIBUTIONS_FILE), "r"))

    anomaly_statistics = []
    for attribution in tqdm(
        attributions, desc="Processing Attributions", unit="attribution"
    ):
        try:
            top_feature = attribution["attributions"][0]["feature"]
            result = compute_anomaly_statistics(
                detection_points=detection_points[attribution["attack_number"]],
                test_dataset=df_test,
                component_name=top_feature,
            )
            result["top_attribution"] = top_feature
        except Exception as e:
            logger.exception(
                f"Error processing attribution {attribution['attack_number']}"
            )
            result = {}
        result["attack_number"] = attribution["attack_number"]
        anomaly_statistics.append(result)

    with open(os.path.join(OUTPUT_DIR, "anomaly_statistics.json"), "w") as f:
        json.dump(anomaly_statistics, f, indent=4)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    main()

import argparse
import json
import logging
import math
import os

import matplotlib.pyplot as plt
import requests
from tqdm import tqdm

logger = logging.getLogger(__name__)


REPO_BASE_URL = "https://raw.githubusercontent.com/siddydutta/ics-anomaly-attribution/refs/heads/main/"
EXPLANATION_URL_TEMPLATE = (
    f"{REPO_BASE_URL}/explanations-dir/explain23-json/"
    "explanations-ensemble-LSTM-SWAT-l2-hist50-units64-results-"
    "{{ATTACK_NUMBER}}-true150.json"
)
EXPLANATIONS_DIR = "data/explanations/"
NUM_ATTACKS = 32
OUTPUT_DIR = "output/"


def fetch_explanation(attack_number: int) -> dict:
    """
    Fetch explanation JSON for a given attack number from the remote repository.

    Args:
        attack_number (int): The attack number.

    Returns:
        dict: The explanation data.

    Raises:
        Exception: If the request fails.
    """
    url = EXPLANATION_URL_TEMPLATE.format(ATTACK_NUMBER=attack_number)
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(
            f"Failed to fetch explanation for attack number {attack_number}. "
            f"Status code: {response.status_code}"
        )


def compute_match_for_k_attributions(k: int) -> float:
    """
    Compute the percentage of attacks where the true label is in the top-k attributions.

    Args:
        k (int): Number of top attributions to consider.

    Returns:
        float: Match percentage.
    """
    match_count = 0
    for attack_number in range(NUM_ATTACKS):
        try:
            with open(
                os.path.join(EXPLANATIONS_DIR, f"attack_{attack_number}.json"), "r"
            ) as f:
                explanation = json.load(f)
                # check for NaN scores
                if math.isnan(explanation["attributions"][0]["score"]):
                    logger.debug(
                        f"NaN score detected for attack {attack_number}. Skipping."
                    )
                    continue
        except FileNotFoundError:
            logger.warning(f"File for attack {attack_number} not found. Skipping.")
            continue
        except json.JSONDecodeError:
            logger.warning(f"Error decoding JSON for attack {attack_number}. Skipping.")
            continue

        top_k_attributions = [
            attribution["feature"] for attribution in explanation["attributions"][:k]
        ]
        if explanation["true_label"] in top_k_attributions:
            match_count += 1
    return match_count / NUM_ATTACKS * 100


def process_top_k_attributions(k: int) -> list:
    """
    Collect the top-k attributions for each attack, rounding scores to 2 decimals and skipping NaNs.

    Args:
        k (int): Number of top attributions to collect.

    Returns:
        list: List of attribution summaries per attack.
    """
    top_k_attributions = []
    for attack_number in range(NUM_ATTACKS):
        try:
            with open(
                os.path.join(EXPLANATIONS_DIR, f"attack_{attack_number}.json"), "r"
            ) as f:
                explanation = json.load(f)
        except FileNotFoundError:
            logger.warning(f"File for attack {attack_number} not found. Skipping.")
            continue
        except json.JSONDecodeError:
            logger.warning(f"Error decoding JSON for attack {attack_number}. Skipping.")
            continue

        attributions = []
        for attribution in explanation["attributions"][:k]:
            score = attribution.get("score")
            if math.isnan(score):
                continue  # Skip NaN scores
            attribution["score"] = round(score, 2)
            attributions.append(attribution)

        attributions_summary = {
            "attack_number": attack_number,
            "true_label": explanation["true_label"],
            "attributions": attributions,
        }
        top_k_attributions.append(attributions_summary)
    return top_k_attributions


def plot_k_vs_match_percentage(k_values, match_percentages, output_dir):
    """
    Plot and save the k vs match percentage chart.

    Args:
        k_values (list): List of k values.
        match_percentages (list): Corresponding match percentages.
        output_dir (str): Directory to save the plot.
    """
    plt.figure(figsize=(8, 5))
    plt.plot(k_values, match_percentages, marker="o")
    plt.xlabel("k (Top-k Attributions)")
    plt.ylabel("Match Percentage (%)")
    plt.title("Top-k Attribution Match Percentage")
    plt.grid(True)
    plt.tight_layout()
    os.makedirs(output_dir, exist_ok=True)
    plt.savefig(os.path.join(output_dir, "k_vs_match_percentage.png"))
    plt.close()


def main():
    """
    Main execution function for processing attributions and plotting results.
    """
    parser = argparse.ArgumentParser(
        description="Process top-k attributions and plot results."
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=60,
        help="Threshold for match percentage (default: 60)",
    )
    args = parser.parse_args()
    threshold = args.threshold

    # Fetch explanations if they do not exist
    os.makedirs(EXPLANATIONS_DIR, exist_ok=True)
    try:
        for attack_number in tqdm(range(NUM_ATTACKS), desc="Fetching explanations"):
            explanation_path = os.path.join(
                EXPLANATIONS_DIR, f"attack_{attack_number}.json"
            )
            if not os.path.exists(explanation_path):
                explanation = fetch_explanation(attack_number=attack_number)
                with open(explanation_path, "w") as f:
                    json.dump(explanation, f, indent=4)
    except Exception as e:
        logger.error(f"Error fetching explanations: {e}")

    # Compute optimal k based on threshold
    k_values = []
    match_percentages = []
    optimal_k = None
    for k in range(1, 25):
        match_percentage = compute_match_for_k_attributions(k)
        logger.info(f"Top-{k} match percentage: {match_percentage:.2f}%")
        k_values.append(k)
        if optimal_k is None and match_percentage >= threshold:
            optimal_k = k
        match_percentages.append(match_percentage)

    plot_k_vs_match_percentage(k_values, match_percentages, OUTPUT_DIR)

    # Store attributions for the optimal k
    if optimal_k is not None:
        logger.info(f"Optimal k found: {optimal_k}")
        attributions = process_top_k_attributions(optimal_k)
        with open(os.path.join(OUTPUT_DIR, "attributions.json"), "w") as f:
            json.dump(attributions, f, indent=4)
        logger.info(
            f"Saved attributions for k={optimal_k} to {os.path.join(OUTPUT_DIR, 'attributions.json')}"
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    main()

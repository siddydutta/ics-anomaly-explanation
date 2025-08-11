import argparse
import json
import logging
import os
from typing import Any, Optional

import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Visualise top attributions for an attack"
    )
    parser.add_argument(
        "--attack",
        type=int,
        required=True,
        help="Attack ID (matches 'attack_number' in JSON; falls back to list index if not found)",
    )
    parser.add_argument(
        "--input",
        type=str,
        default="output/attributions.json",
        help="Path to attributions JSON",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="output/plots",
        help="Directory to save the chart",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Number of top features to plot",
    )
    return parser.parse_args()


def load_data(path: str) -> list[dict[str, Any]]:
    with open(path, "r") as f:
        return json.load(f)


def find_attack_entry(
    data: list[dict[str, Any]], attack_id: int
) -> Optional[dict[str, Any]]:
    for entry in data:
        if entry.get("attack_number") == attack_id:
            return entry
    return None


def plot_attributions(
    entry: dict[str, Any],
    out_dir: str,
    top_k: int,
) -> str:
    os.makedirs(out_dir, exist_ok=True)

    attack_id = entry.get("attack_number", "unknown")
    atts = entry.get("attributions", []) or []

    fname = os.path.join(out_dir, f"attribution_attack_{attack_id}.png")

    if not atts:
        logger.warning(
            "Attack %s has no attributions. Saving placeholder plot.", attack_id
        )
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.axis("off")
        ax.text(
            0.5,
            0.5,
            f"No attributions to display\n(attack {attack_id})",
            ha="center",
            va="center",
            fontsize=12,
        )
        fig.tight_layout()
        fig.savefig(fname, bbox_inches="tight")
        plt.close(fig)
        return fname

    # Sort and take top-k
    atts_sorted = sorted(atts, key=lambda x: x.get("score", 0.0), reverse=True)[:top_k]
    features = [a.get("feature", "") for a in atts_sorted][
        ::-1
    ]  # reverse for barh top-to-bottom
    scores = [a.get("score", 0.0) for a in atts_sorted][::-1]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(range(len(features)), scores, color="#377eb8")
    ax.set_yticks(range(len(features)))
    ax.set_yticklabels(features)
    ax.set_xlabel("Attribution score")
    ax.set_title(f"Attack Component Attributions - Top Component: {features[-1]}")
    ax.grid(axis="x", linestyle="--", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fname, bbox_inches="tight")
    plt.close(fig)
    return fname


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    args = parse_args()
    logger.info("Loading attributions from %s", args.input)
    try:
        data = load_data(args.input)
        entry = find_attack_entry(data, args.attack)
        if entry is None:
            logger.error("Attack %d not found in %s", args.attack, args.input)
            return
        out_path = plot_attributions(entry, args.output_dir, args.top_k)
        logger.info("Saved plot to %s", out_path)
    except Exception:
        logger.exception("Failed to visualise attributions")


if __name__ == "__main__":
    main()

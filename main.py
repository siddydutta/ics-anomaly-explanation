import argparse
import logging
import os

from dotenv import load_dotenv

from constants import VARIANT_MAP
from ics_anomaly_explainer import ICSAnomalyExplainer

load_dotenv()


logger = logging.getLogger(__name__)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Run ICS anomaly explanation experiments"
    )
    parser.add_argument(
        "--attack", type=int, required=True, help="Attack ID to process"
    )
    parser.add_argument(
        "--variant",
        type=str,
        required=True,
        choices=["BASELINE", "NO_MITRE", "FULL"],
        help="Experiment variants to run",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="output/",
        help="Output directory for results",
    )
    args = parser.parse_args()

    # Validate output directory
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        logger.debug(f"Created output directory: {args.output_dir}")

    # Run the experiment based on the variant
    logger.info(f"\nExperiment for attack {args.attack} with variant {args.variant}")
    try:
        variant = VARIANT_MAP[args.variant]
        explainer = ICSAnomalyExplainer(variant, args.attack)
        result = explainer.run_experiment()
        explainer.save_results(args.output_dir, result)
        logger.info(
            f"Experiment for attack {args.attack} with variant {args.variant} completed successfully"
        )
    except Exception as e:
        logger.exception("Error running experiment")


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    main()

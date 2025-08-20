# SWaT Attack   38
# Multi Stage Single Point Attack
# Start Time:   2/01/2015 11:31:38
# End Time:     2/01/2015 11:36:18
# Attack Point: AIT‐402, AIT‐502
# Start State:  In Normal Range
# Attack:       Set value of AIT402 as 260; Set value of AIT5
# Expected:     Water goes to drain because of overdosing
# Actual:       Water did not go to the drain

# Attack Ensembled-Method Attributions
# "attributions": [
#     {
#         "feature": "AIT201",
#         "score": 51.51
#     },
#     {
#         "feature": "AIT402",
#         "score": 11.6
#     },
#     {
#         "feature": "AIT502",
#         "score": 9.51
#     },
#     {
#         "feature": "P101",
#         "score": 9.11
#     },
#     {
#         "feature": "P302",
#         "score": 7.91
#     }
# ]

import argparse
import json
import logging
import os

from dotenv import load_dotenv
from llama_cloud import (
    FilterCondition,
    FilterOperator,
    MetadataFilter,
    MetadataFilters,
    RetrievalMode,
)
from llama_index.indices.managed.llama_cloud import LlamaCloudIndex
from llama_index.llms.openai import OpenAI
from pydantic import BaseModel, Field
from tqdm import tqdm

from config import (
    LLAMA_INDEX_NAME,
    LLAMA_PROJECT_NAME,
    OPENAI_MODEL,
    OPENAI_TEMPERATURE,
)
from process_anomalies import (
    ATTRIBUTIONS_FILE,
    OUTPUT_DIR,
    compute_anomaly_statistics,
    fetch_detection_points,
    retrieve_swat_data,
)

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

ATTACK_INDEX = 28
TOP_K = 3
EXPLANATION_PROMPT = """
You are an expert in industrial control systems security.

An anomaly was detected in the components: {features}

*************
Statistical evidence for each feature:
{anomaly_stats}

Context:
{context}
*************

Provide a concise, data-driven analysis. Keep each response field to 2-3 sentences maximum. Focus on specifics based on the statistical evidence rather than generic possibilities.

Analyse:
- The component functions and what the statistical pattern indicates physically happened
- Specific impacts based on this components role in the stages and the statistical evidence

Base analysis strictly on provided context.
"""


class ExplanationOutput(BaseModel):
    """Output for final concise anomaly explanation."""

    explanation: str = Field(
        ...,
        description="Brief explanation of the components and what happened based on statistical evidence (2-3 sentences)",
    )
    potential_impact: str = Field(
        ...,
        description="Specific impacts based on these components' roles and statistical evidence (2-3 sentences)",
    )


def prepare_anomaly_statistics(attribution, detection_points, df_test):
    anomaly_statistics = dict()
    for attr in tqdm(attribution["attributions"], desc="Processing attributions"):
        component = attr["feature"]
        statistics = compute_anomaly_statistics(
            detection_points=detection_points[attribution["attack_number"]],
            test_dataset=df_test,
            component_name=component,
        )
        baseline = statistics["baseline_stats"]
        detected = statistics["detected_stats"]
        change_direction = "↑" if detected["mean"] > baseline["mean"] else "↓"
        signature = "sudden change" if detected["std"] < 0.1 else "variable behavior"
        anomaly_statistics[component] = (
            f"Baseline: {baseline['mean']:.2f}±{baseline['std']:.2f} → Detected: {detected['mean']:.2f}±{detected['std']:.2f} ({change_direction}{statistics['detected_change_percent']}, {signature})"
        )
    return anomaly_statistics


def prepare_documents(attribution, index):
    documents = dict()
    for attr in tqdm(attribution["attributions"], desc="Retrieving documents"):
        feature = attr["feature"]
        filters = [
            MetadataFilter(
                key="component_id", operator=FilterOperator.EQUAL_TO, value=feature
            )
        ]
        for ch in feature:
            if ch.isdigit():
                filters.append(
                    MetadataFilter(
                        key="stage_id", operator=FilterOperator.EQUAL_TO, value=f"P{ch}"
                    )
                )
                break

        retriever = index.as_retriever(
            retrieval_mode=RetrievalMode.CHUNKS,
            dense_similarity_top_k=TOP_K,
            sparse_similarity_top_k=TOP_K,
            alpha=0.5,
            enable_reranking=True,
            rerank_top_n=TOP_K,
            filters=MetadataFilters(filters=filters, condition=FilterCondition.OR),
        )
        documents[feature] = retriever.retrieve(feature)
    return documents


def build_prompt(variant, attribution, documents, anomaly_statistics):
    if variant == "IDEAL":
        components = ["AIT402", "AIT502"]
    elif variant == "COMPLEX":
        components = [attribution["attributions"][0]["feature"]]
    elif variant == "TOP":
        components = [attr["feature"] for attr in attribution["attributions"][:TOP_K]]
    else:
        raise ValueError("Unknown variant")

    nodes = [node for component in components for node in documents[component]]
    context = "\n---\n".join(
        [
            f"Source Type: {node.metadata.get('doc_type', 'Unknown')}\n{node.text}"
            for node in nodes
        ]
    )
    attack_statistics = {
        component: anomaly_statistics[component] for component in components
    }
    prompt = EXPLANATION_PROMPT.format(
        features=", ".join(components), context=context, anomaly_stats=attack_statistics
    )
    return prompt


def main():
    parser = argparse.ArgumentParser(description="Run stress test variants")
    parser.add_argument(
        "--variant",
        type=str,
        required=True,
        choices=["IDEAL", "COMPLEX", "TOP"],
        help="Variant to run: IDEAL, COMPLEX, or TOP",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="output/stress-test",
        help="Directory to store output",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    output_path = os.path.join(args.output_dir, args.variant + ".json")

    LLM = OpenAI(
        model=OPENAI_MODEL,
        api_key=os.getenv("OPENAI_API_KEY"),
        temperature=OPENAI_TEMPERATURE,
    )
    INDEX = LlamaCloudIndex(
        LLAMA_INDEX_NAME,
        project_name=LLAMA_PROJECT_NAME,
        api_key=os.getenv("LLAMA_CLOUD_API_KEY"),
    )

    detection_points = fetch_detection_points()
    df_test = retrieve_swat_data("test")
    attribution = json.load(open(os.path.join(OUTPUT_DIR, ATTRIBUTIONS_FILE), "r"))[
        ATTACK_INDEX
    ]

    anomaly_statistics = prepare_anomaly_statistics(
        attribution, detection_points, df_test
    )
    documents = prepare_documents(attribution, INDEX)

    prompt = build_prompt(args.variant, attribution, documents, anomaly_statistics)
    logger.info(f"Generated prompt:\n{prompt}")

    response = LLM.as_structured_llm(output_cls=ExplanationOutput).complete(
        prompt=prompt
    )
    explanation = ExplanationOutput.model_validate(json.loads(response.text))

    with open(output_path, "w") as f:
        json.dump(explanation.model_dump(), f, indent=2)

    logger.info(f"Output written to {output_path}")


if __name__ == "__main__":
    main()

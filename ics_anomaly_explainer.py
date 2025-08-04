import json
import logging
import os
import time
from dataclasses import asdict
from typing import Optional

import tiktoken
from llama_cloud import (
    FilterCondition,
    FilterOperator,
    MetadataFilter,
    MetadataFilters,
    RetrievalMode,
)
from llama_index.core.callbacks import CallbackManager, TokenCountingHandler
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core.schema import NodeWithScore
from llama_index.indices.managed.llama_cloud import LlamaCloudIndex
from llama_index.llms.openai import OpenAI

from config import (
    ATTRIBUTIONS_FILE,
    LLAMA_INDEX_NAME,
    LLAMA_PROJECT_NAME,
    OPENAI_MODEL,
    OPENAI_TEMPERATURE,
)
from constants import MITRE_TACTICS
from models import (
    ExperimentResult,
    ExperimentVariant,
    ExplanationOutput,
    StageMetrics,
    TacticsOutput,
)
from prompts import EXPLANATION_PROMPT_MAP, MITRE_FILTER_INFERENCE


class ICSAnomalyExplainer:
    """Main class for ICS anomaly explanation pipeline."""

    def __init__(self, variant: ExperimentVariant, attack_id: int):
        self.logger = logging.getLogger(__name__)
        self.variant = variant
        self.attack_id = attack_id
        with open(ATTRIBUTIONS_FILE, "r") as f:
            attributions = json.load(f)[self.attack_id]
            self.top_feature = attributions["attributions"][0]["feature"]

        self.token_counter = TokenCountingHandler(
            tokenizer=tiktoken.encoding_for_model(OPENAI_MODEL).encode
        )
        self.llm = OpenAI(
            model=OPENAI_MODEL,
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=OPENAI_TEMPERATURE,
            callback_manager=CallbackManager([self.token_counter]),
        )
        self.index = LlamaCloudIndex(
            LLAMA_INDEX_NAME,
            project_name=LLAMA_PROJECT_NAME,
            api_key=os.getenv("LLAMA_CLOUD_API_KEY"),
        )
        self.nodes: list[NodeWithScore] = []
        self.stages: list[StageMetrics] = []

    def __add_stage_metrics(
        self, stage_name: str, latency: float, retrieved_docs: int = 0
    ):
        """Helper method to add stage metrics."""
        self.stages.append(
            StageMetrics(
                stage_name=stage_name,
                latency_seconds=latency,
                embedding_tokens=self.token_counter.total_embedding_token_count,
                input_tokens=self.token_counter.prompt_llm_token_count,
                output_tokens=self.token_counter.completion_llm_token_count,
                retrieved_docs=retrieved_docs,
            )
        )
        self.token_counter.reset_counts()

    def __get_heuristic_filters(self, top_feature: str) -> MetadataFilters:
        """Generate metadata filters based on the top attribution feature."""
        filters = [
            MetadataFilter(
                key="component_id", operator=FilterOperator.EQUAL_TO, value=top_feature
            )
        ]
        for ch in top_feature:
            if ch.isdigit():
                filters.append(
                    MetadataFilter(
                        key="stage_id", operator=FilterOperator.EQUAL_TO, value=f"P{ch}"
                    )
                )
                break
        return MetadataFilters(filters=filters, condition=FilterCondition.OR)

    def __retrieve_documents(
        self, query: str, filters: Optional[MetadataFilters] = None, top_k: int = 3
    ) -> list[NodeWithScore]:
        """Retrieve document chunks from the index."""
        retriever = self.index.as_retriever(
            retrieval_mode=RetrievalMode.CHUNKS,
            dense_similarity_top_k=top_k,
            sparse_similarity_top_k=top_k,
            alpha=0.5,
            enable_reranking=True,
            rerank_top_n=top_k,
            filters=filters,
        )
        return retriever.retrieve(query)

    def __infer_mitre_filters(
        self, top_feature: str, swat_nodes: list[NodeWithScore]
    ) -> tuple[MetadataFilters, str]:
        """Infer MITRE ATT&CK filters based on the top attribution feature."""
        context = "\n".join([node.text for node in swat_nodes])
        prompt = MITRE_FILTER_INFERENCE.format(
            top_feature=top_feature,
            context=context,
            MITRE_TACTICS=MITRE_TACTICS,
        )
        response = self.llm.as_structured_llm(output_cls=TacticsOutput).complete(
            prompt=prompt,
        )
        output = TacticsOutput.model_validate(json.loads(response.text))
        filters = MetadataFilters(
            filters=[
                MetadataFilter(
                    key="source", operator=FilterOperator.EQUAL_TO, value="MITRE_ICS"
                ),
                MetadataFilter(
                    key="doc_type",
                    operator=FilterOperator.EQUAL_TO,
                    value="attack_technique",
                ),
                MetadataFilter(
                    key="tactic", operator=FilterOperator.IN, value=output.tactics
                ),
            ],
            condition=FilterCondition.AND,
        )
        return filters, output.reasoning

    def generate_explanation(self) -> ExplanationOutput:
        context = "\n---\n".join(
            [
                f"Source Type: {node.metadata.get('doc_type', 'Unknown')}\n{node.text}"
                for node in self.nodes
            ]
        )
        prompt = EXPLANATION_PROMPT_MAP[self.variant]
        prompt = prompt.format(top_feature=self.top_feature, context=context)
        response = self.llm.as_structured_llm(output_cls=ExplanationOutput).complete(
            prompt=prompt
        )
        output = ExplanationOutput.model_validate(json.loads(response.text))
        return output

    def run_experiment(self) -> ExperimentResult:
        """Run a complete experiment on a specific attack for a given variant."""
        total_start_time = time.perf_counter()

        # Step 1: Retrieve SWaT documents
        if (
            self.variant == ExperimentVariant.NO_MITRE
            or self.variant == ExperimentVariant.FULL
        ):
            filters = self.__get_heuristic_filters(top_feature=self.top_feature)
        else:
            filters = None
        retrieve_swat_start_time = time.perf_counter()
        self.logger.info(f"[FILTERS] SWaT: {filters}")
        swat_doc_nodes = self.__retrieve_documents(
            query=self.top_feature, filters=filters
        )
        retrieve_swat_latency = time.perf_counter() - retrieve_swat_start_time
        self.logger.info(f"[DOCUMENTS] SWaT: {swat_doc_nodes}")
        self.nodes.extend(swat_doc_nodes)
        self.__add_stage_metrics(
            stage_name="swat_document_retrieval",
            latency=retrieve_swat_latency,
            retrieved_docs=len(swat_doc_nodes),
        )

        # Step 2: Retrieve MITRE ATT&CK tactics
        if self.variant == ExperimentVariant.FULL:
            retrieve_mitre_start_time = time.perf_counter()
            filters, reasoning = self.__infer_mitre_filters(
                top_feature=self.top_feature, swat_nodes=swat_doc_nodes
            )
            mitre_doc_nodes = self.__retrieve_documents(
                query=reasoning, filters=filters
            )
            retrieve_mitre_latency = time.perf_counter() - retrieve_mitre_start_time
            self.logger.info(f"[FILTERS] MITRE: {filters}")
            self.logger.info(f"[DOCUMENTS] MITRE: {mitre_doc_nodes}")
            self.nodes.extend(mitre_doc_nodes)
            self.__add_stage_metrics(
                stage_name="mitre_document_retrieval",
                latency=retrieve_mitre_latency,
                retrieved_docs=len(mitre_doc_nodes),
            )
        else:
            reasoning = None
            self.__add_stage_metrics(
                stage_name="mitre_document_retrieval",
                latency=0.0,
                retrieved_docs=0,
            )

        # Step 3: Generate final explanation
        explanation_start_time = time.perf_counter()
        explanation = self.generate_explanation()
        explanation_latency = time.perf_counter() - explanation_start_time
        self.logger.info(f"[EXPLANATION] {explanation}")
        self.__add_stage_metrics(
            stage_name="explanation_generation",
            latency=explanation_latency,
        )

        total_latency = time.perf_counter() - total_start_time
        context_nodes = [node.node.text for node in self.nodes]
        return ExperimentResult(
            variant=self.variant.value,
            attack_id=self.attack_id,
            top_feature=self.top_feature,
            stages=self.stages,
            inference=reasoning,
            explanation=explanation.model_dump(),
            total_latency=total_latency,
            context_nodes=context_nodes,
        )

    def save_results(self, output_dir: str, result: ExperimentResult) -> None:
        """Save all experimental results to JSON file."""
        results_dict = asdict(result)

        output_file = os.path.join(
            output_dir, f"experiment_results_{self.variant.value}_{self.attack_id}.json"
        )
        with open(output_file, "w") as f:
            json.dump(results_dict, f, indent=2, default=str)

        self.logger.info(f"Results saved to {output_file}")

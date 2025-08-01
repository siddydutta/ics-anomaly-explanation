import json
import os

from dotenv import load_dotenv
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core.response_synthesizers import ResponseMode
from llama_index.core.vector_stores.types import (
    MetadataFilters,
    MetadataInfo,
    VectorStoreInfo,
    VectorStoreQuerySpec,
)
from llama_index.indices.managed.llama_cloud import LlamaCloudIndex
from llama_index.llms.openai import OpenAI

from retriever_config import CHAT_PROMPT_TEMPLATE, VECTOR_STORE_INFO

load_dotenv()

index = LlamaCloudIndex(
    "ICS Knowledge Base",
    project_name="Default",
    api_key=os.getenv("LLAMA_CLOUD_API_KEY"),
)
llm = OpenAI(model="gpt-4o-mini", api_key=os.getenv("OPENAI_API_KEY"))

attributions = [
    {"feature": "MV101", "score": 17.56},
    {"feature": "MV201", "score": 15.42},
    {"feature": "P101", "score": 15.02},
    {"feature": "PIT502", "score": 12.37},
    {"feature": "P203", "score": 9.93},
]

query_spec = llm.structured_predict(
    VectorStoreQuerySpec,
    CHAT_PROMPT_TEMPLATE,
    info_str=VECTOR_STORE_INFO.model_dump_json(indent=4),
    schema_str=json.dumps(VectorStoreQuerySpec.model_json_schema()),
    query_str=f"Anomaly detected with the following attributions: {json.dumps(attributions)}. Please provide possible explanations, related components, probable attack techniques for anomaly triage.",
)
filters = (
    MetadataFilters(filters=query_spec.filters) if len(query_spec.filters) > 0 else None
)
print(f"> Inferred query string: {query_spec.query}")
if filters:
    print(f"> Inferred filters: {filters.json()}")
retriever = index.as_retriever(retrieval_mode="chunks", rerank_top_n=5, filters=filters)
query_engine = RetrieverQueryEngine.from_args(
    retriever,
    llm=llm,
    response_mode=ResponseMode.SIMPLE_SUMMARIZE,
)
response = query_engine.query(query_spec.query)
print(f"> Response: {response}")

"""
metadata={'prompt_type': <PromptType.CUSTOM: 'custom'>} template_vars=['schema_str', 'info_str', 'additional_instructions', 'query_str'] kwargs={'additional_instructions': '\n'} output_parser=None template_var_mappings=None function_mappings=None message_templates=[ChatMessage(role=<MessageRole.SYSTEM: 'system'>, additional_kwargs={}, blocks=[TextBlock(block_type='text', text="Your goal is to structure the user's query to match the request schema provided below.\nYou MUST call the tool in order to generate the query spec.\n\n<< Structured Request Schema >>\nWhen responding use a markdown code snippet with a JSON object formatted in the following schema:\n\n{schema_str}\n\nThe query string should contain only text that is expected to match the contents of documents. Any conditions in the filter should not be mentioned in the query as well.\n\nMake sure that filters only refer to attributes that exist in the data source.\nMake sure that filters take into account the descriptions of attributes.\nMake sure that filters are only used as needed. If there are no filters that should be applied return [] for the filter value.\nIf the user's query explicitly mentions number of documents to retrieve, set top_k to that number, otherwise do not set top_k.\n\nThe schema of the metadata filters in the vector db table is listed below.\nThe user will send the input query string.\n\nData Source:\n```json\n{info_str}\n```\n\nAdditional Instructions:\n{additional_instructions}\n")]), ChatMessage(role=<MessageRole.USER: 'user'>, additional_kwargs={}, blocks=[TextBlock(block_type='text', text='{query_str}')])]
> Inferred query string: Anomaly detected with features MV101, MV201, P101, PIT502, P203. Possible explanations, related components, and probable attack techniques for anomaly triage.
> Response: The detected anomaly involves several components, each with specific roles in the system. 

1. **MV101**: This component is an on/off valve connected to T101. Its malfunction could disrupt flow control, potentially leading to improper dosing or system pressure issues.

2. **MV201**: This is another on/off valve, specifically for the raw water tank outlet. It is electric actuated and made of PVC. Issues here could affect the flow of treated water, impacting downstream processes.

3. **P101**: While specific details about P101 are not provided, it is likely a pump or similar device involved in the process, which could be critical for maintaining flow rates or chemical dosing.

4. **PIT502**: This component connects to AIT504, suggesting it plays a role in monitoring or controlling a specific parameter, possibly related to pressure or flow.

5. **P203**: This is a dosing pump for NaOCl, which is essential for disinfection. Anomalies here could lead to inadequate disinfection, posing health risks.

Possible explanations for the anomaly could include:
- Mechanical failure of valves or pumps.
- Electrical issues affecting actuators or sensors.
- Incorrect chemical dosing due to pump malfunction.
- Communication failures between components.

Related components that may also be affected include flow indicators and analyzer transmitters, which monitor chemical properties and flow rates. 

Probable attack techniques could involve:
- Manipulation of control signals to valves or pumps.
- Interference with sensor readings to mislead operators.
- Physical tampering with dosing equipment to alter chemical concentrations.

Addressing these anomalies requires a thorough investigation of the affected components and their interactions within the system.
"""

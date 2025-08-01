from llama_index.core.prompts import ChatPromptTemplate
from llama_index.core.vector_stores.types import MetadataInfo, VectorStoreInfo

VECTOR_STORE_INFO = VectorStoreInfo(
    content_info="Contains information about the SWaT dataset stages, piping & instrumentation diagrams and components, as well as attach techniques from the MITRE ATT&CK ICS framework.",
    metadata_info=[
        MetadataInfo(
            name="source",
            type="str",
            description="Source of the document: SWaT_DOC or MITRE_ICS",
        ),
        MetadataInfo(
            name="doc_type",
            type="str",
            description="Type of document: attack_technique, component, pid or stage",
        ),
        MetadataInfo(
            name="technique_id",
            type="str",
            description="ID of the technique, if applicable (e.g., Txxxx for MITRE ATT&CK techniques)",
        ),
        MetadataInfo(
            name="tactic",
            type="str",
            description="Tactic of the technique, if applicable (e.g., Impact, Lateral Movement, etc.)",
        ),
        MetadataInfo(
            name="component_id",
            type="str",
            description="ID of the SWaT component equipment (e.g., P101, P102, etc.)",
        ),
        MetadataInfo(
            name="stage_id",
            type="str",
            description="Stage of the SWaT dataset (e.g., P1, P2 ... P6)",
        ),
    ],
)

SYS_PROMPT = """\
Your goal is to structure the user's query to match the request schema provided below.
You MUST call the tool in order to generate the query spec.

<< Structured Request Schema >>
When responding use a markdown code snippet with a JSON object formatted in the \
following schema:

{schema_str}

The query string should contain only text that is expected to match the contents of \
documents. Any conditions in the filter should not be mentioned in the query as well.

Make sure that filters only refer to attributes that exist in the data source.
Make sure that filters take into account the descriptions of attributes.
Make sure that filters are only used as needed. If there are no filters that should be \
applied return [] for the filter value.\

If the user's query explicitly mentions number of documents to retrieve, set top_k to \
that number, otherwise do not set top_k.

The schema of the metadata filters in the vector db table is listed below.
The user will send the input query string.

Data Source:
```json
{info_str}
```

Additional Instructions:
{additional_instructions}
"""

# TODO @siddydutta: Add additional instructions to the prompt
ADDITIONAL_INSTRUCTIONS = """\

"""

CHAT_PROMPT_TEMPLATE = ChatPromptTemplate.from_messages(
    [
        ("system", SYS_PROMPT),
        ("user", "{query_str}"),
    ]
)
CHAT_PROMPT_TEMPLATE = CHAT_PROMPT_TEMPLATE.partial_format(
    additional_instructions=ADDITIONAL_INSTRUCTIONS
)

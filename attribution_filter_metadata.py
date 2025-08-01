from llama_index.core.vector_stores import (
    FilterOperator,
    MetadataFilter,
    MetadataFilters,
)
from llama_index.indices.managed.llama_cloud import LlamaCloudIndex

attributions = [
    {"feature": "MV101", "score": 17.56},
    {"feature": "MV201", "score": 15.42},
    {"feature": "P101", "score": 15.02},
    {"feature": "PIT502", "score": 12.37},
    {"feature": "P203", "score": 9.93},
]


# create metadata filter
filters = MetadataFilters(
    filters=[
        MetadataFilter(key="theme", operator=FilterOperator.EQ, value="Fiction"),
    ]
)

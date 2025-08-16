import altair as alt
import pandas as pd

DATA_FILE = "user-evaluation.csv"

CONDITION_RAW = "RAW"
CONDITION_BASE = "BASE"
CONDITION_FULL = "FULL"
CONDITIONS = [CONDITION_RAW, CONDITION_BASE, CONDITION_FULL]
CONDITION_MAP = {
    "RAW": "RAW XAI",
    "BASE": "N-RAG",
    "FULL": "ME-RAG",
}
CONDITION_COLOURS = {
    "ME-RAG": "#000000",  # Black
    "N-RAG": "#7f7f7f",  # Dark Gray
    "RAW XAI": "#cccccc",  # Light Gray
}


METRIC_CONFIDENCE = "I am confident I understand the core problem."
METRIC_ACTIONABILITY = "I have a clear idea of the potential impact on the system."
METRIC_COGNITIVE_LOAD = (
    "It required a high degree of mental effort to understand this information."
)
METRIC_CLARITY = "The text explanation was easy to understand."
METRIC_TRUSTWORTHINESS = "I trust the information presented in the text explanation."
METRICS = [
    METRIC_CONFIDENCE,
    METRIC_ACTIONABILITY,
    METRIC_COGNITIVE_LOAD,
    METRIC_CLARITY,
    METRIC_TRUSTWORTHINESS,
]
METRIC_MAP = {
    METRIC_CONFIDENCE: "Confidence",
    METRIC_ACTIONABILITY: "Actionability",
    METRIC_COGNITIVE_LOAD: "Cognitive Load",
    METRIC_CLARITY: "Clarity",
    METRIC_TRUSTWORTHINESS: "Trustworthiness",
}

raw_df = pd.read_csv(DATA_FILE)

# Map Qualtrics Survey's QID columns to experiment condition and metric.
COLUMN_MAP = dict()
for column, question in zip(raw_df.columns, raw_df.iloc[0]):
    mapping = dict()
    for condition in CONDITIONS:
        if condition in question:
            mapping["condition"] = CONDITION_MAP[condition]
            break
    for metric in METRICS:
        if metric in question:
            mapping["metric"] = METRIC_MAP[metric]
            break
    if mapping:
        COLUMN_MAP[column] = mapping


# Transform the data from a "wide" format (one column per question)
# to a "long" format (one column for the condition, one for the metric, one for the value).
long_format_data = []
for col_name, mapping in COLUMN_MAP.items():
    if col_name in raw_df.columns:
        for value in raw_df[col_name].iloc[2:].dropna():
            long_format_data.append(
                {
                    "Condition": mapping["condition"],
                    "Metric": mapping["metric"],
                    "Score": value,
                }
            )
df_long = pd.DataFrame(long_format_data)
# Ensure Score is numeric for aggregation
df_long["Score"] = pd.to_numeric(df_long["Score"], errors="coerce")

# Print mean Likert scores for each (Condition, Metric) pair
mean_scores = df_long.groupby(["Condition", "Metric"])["Score"].mean().unstack()
print(
    "--------------- Mean Likert Scores (1-5) by Condition and Metric ---------------"
)
print(mean_scores)

# Define the metrics for the first chart
metrics_chart_1 = ["Confidence", "Actionability", "Cognitive Load"]
data_chart_1 = df_long[df_long["Metric"].isin(metrics_chart_1)]

# Define the metrics for the second chart
metrics_chart_2 = ["Clarity", "Trustworthiness"]
data_chart_2 = df_long[df_long["Metric"].isin(metrics_chart_2)]

chart1 = (
    alt.Chart(data_chart_1)
    .mark_bar()
    .encode(
        x=alt.X(
            "Metric:N",
            title="Metric",
            axis=alt.Axis(labelAngle=0),
            sort=metrics_chart_1,
        ),
        y=alt.Y("mean(Score):Q", title="Mean Likert Score (1-5)"),
        color=alt.Color(
            "Condition:N",
            title="Condition",
            scale=alt.Scale(
                domain=list(CONDITION_COLOURS.keys()),
                range=list(CONDITION_COLOURS.values()),
            ),
            legend=alt.Legend(labelFontSize=12, titleFontSize=13),
        ),
        xOffset="Condition:N",
    )
    .properties(title="", width=alt.Step(40))
)

chart2 = (
    alt.Chart(data_chart_2)
    .mark_bar()
    .encode(
        x=alt.X("Metric:N", title="Metric", axis=alt.Axis(labelAngle=0)),
        y=alt.Y(
            "mean(Score):Q",
            title="Mean Likert Score (1-5)",
            axis=alt.Axis(orient="right"),
        ),
        color=alt.Color(
            "Condition:N",
            title="Condition",
            scale=alt.Scale(
                domain=list(CONDITION_COLOURS.keys()),
                range=list(CONDITION_COLOURS.values()),
            ),
            legend=alt.Legend(labelFontSize=12, titleFontSize=13),
        ),
        xOffset="Condition:N",
    )
    .properties(title="", width=alt.Step(40))
)

chart = alt.hconcat(chart1, chart2)
chart.save("user-evaluation-metrics.png")

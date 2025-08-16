import csv
import json
import os

# Constants
ATTACKS = [0, 1, 3, 5, 6, 11, 13, 14]
VARIANTS = ["BASELINE", "FULL"]
INPUT_COST_PER_M = 0.25
OUTPUT_COST_PER_M = 0.60
RESULTS_DIR = "../output/experiment-results"
CSV_OUT = "performance-evaluation.csv"
ONE_MILLION = 1_000_000
HEADER = [
    "Attack Index (AXIS)",
    "Attack ID (SWaT)",
    "Input Tokens (N-RAG)",
    "Input Tokens (ME-RAG)",
    "Output Tokens (N-RAG)",
    "Output Tokens (ME-RAG)",
    "Latency (s) (N-RAG)",
    "Latency (s) (ME-RAG)",
    "Cost ($) (N-RAG)",
    "Cost ($) (ME-RAG)",
]
SWAT_ATTACK_IDS = {0: 1, 1: 2, 3: 6, 5: 8, 6: 10, 11: 20, 13: 22, 14: 23}

rows = []
for attack in ATTACKS:
    row = [attack, SWAT_ATTACK_IDS.get(attack, attack)]
    for variant in VARIANTS:
        fname = f"attack_{attack}_{variant}.json"
        fpath = os.path.join(RESULTS_DIR, fname)
        input_tokens = output_tokens = latency = 0
        cost = 0.0
        if os.path.exists(fpath):
            with open(fpath, "r") as f:
                data = json.load(f)
                # Sum tokens from all stages
                input_tokens = sum(
                    s.get("input_tokens", 0) for s in data.get("stages", [])
                )
                output_tokens = sum(
                    s.get("output_tokens", 0) for s in data.get("stages", [])
                )
                latency = data["total_latency"]
                cost = (input_tokens / ONE_MILLION * INPUT_COST_PER_M) + (
                    output_tokens / ONE_MILLION * OUTPUT_COST_PER_M
                )
        row.extend([input_tokens, output_tokens, round(latency, 2), round(cost, 4)])
    rows.append(row)

# Write CSV
with open(CSV_OUT, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(HEADER)
    print("\t".join(HEADER))
    for row in rows:
        out_row = [
            row[0],
            row[1],  # Attack Index, Attack ID
            row[2],
            row[6],  # Input Tokens N-RAG, ME-RAG
            row[3],
            row[7],  # Output Tokens N-RAG, ME-RAG
            row[4],
            row[8],  # Latency N-RAG, ME-RAG
            row[5],
            row[9],  # Cost N-RAG, ME-RAG
        ]
        writer.writerow(out_row)
        print("\t".join(map(str, out_row)))

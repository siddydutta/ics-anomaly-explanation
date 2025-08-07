#!/bin/bash

OUTPUT_DIR="output/experiment-results/"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Raise error if attack index is not provided
if [ -z "$1" ]; then
    echo "Error: Attack index must be provided as the first argument."
    exit 1
fi

# Take attack index as an argument
ATTACK_NUM="$1"

# Run experiments for the specified attack and each variant
for variant in "BASELINE" "NO_MITRE" "FULL"; do
    python main.py --attack "$ATTACK_NUM" --variant "$variant" --output-dir "$OUTPUT_DIR"
done

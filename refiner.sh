#!/usr/bin/env bash

set -euo pipefail

# ====== CONFIG ======
OUTPUT_DIR="v2ray-configs"
REFINED_DIR="$OUTPUT_DIR"
DEFAULT_INPUT="input.txt"

# ====== FUNCTIONS ======

print_usage() {
  echo "Usage: $0 [input_file]"
}

ensure_dirs() {
  mkdir -p "$REFINED_DIR"
}

validate_input() {
  local file="$1"

  if [[ ! -f "$file" ]]; then
    echo "❌ Error: Input file '$file' not found."
    exit 1
  fi

  if [[ ! -s "$file" ]]; then
    echo "❌ Error: Input file is empty."
    exit 1
  fi
}

refine_configs() {
  local input_file="$1"
  local output_file="$2"

  sed -E 's/@[^:]+:[0-9]+/@127.0.0.1:40443/g' "$input_file" > "$output_file"
}

main() {
  local input_file="${1:-$DEFAULT_INPUT}"
  local output_file

  validate_input "$input_file"
  ensure_dirs


  output_file="$REFINED_DIR/refined-v2ray.txt"
  
  refine_configs "$input_file" "$output_file"

  echo "✅ Refinement complete"
  echo "📥 Input : $input_file"
  echo "📤 Output: $output_file"
}

# ====== ENTRY POINT ======
main "$@"
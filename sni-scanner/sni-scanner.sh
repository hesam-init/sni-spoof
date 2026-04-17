#!/bin/bash
# =============================================================================
# SNI Scanner — Parallel Edition
# Author : SeRaMo (https://github.com/seramo/)
# Usage  : ./sni_scanner.sh [targets.txt] [parallel-jobs]
# =============================================================================

# ── Configuration ─────────────────────────────────────────────────────────────

TARGET_FILE="${1:-targets.txt}"
PARALLEL_JOBS="${2:-10}"
PORTS=(443 2053 2083 2087 2096 8443)

# ── Validation ────────────────────────────────────────────────────────────────

die() { echo "Error: $*" >&2; exit 1; }

[[ -f "$TARGET_FILE" ]]          || die "File '$TARGET_FILE' not found."
command -v parallel &>/dev/null  || die "GNU Parallel is not installed.\n  → sudo apt install parallel   OR   brew install parallel"

# ── Temp files (one per result bucket) ────────────────────────────────────────

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT      # always clean up on exit

FILE_OK="$TMPDIR/ok"
FILE_FAIL="$TMPDIR/fail"
FILE_NORESOLVE="$TMPDIR/noresolve"
touch "$FILE_OK" "$FILE_FAIL" "$FILE_NORESOLVE"

# ── Helper: append a line to a file safely across parallel workers ─────────────

safe_append() {
  local line="$1"
  local file="$2"
  (flock 9; echo "$line" >> "$file") 9>"${file}.lock"
}
export -f safe_append

# ── Helper: resolve a domain to one or more IPv4 addresses ────────────────────

resolve_domain() {
  dig +short "$1" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
}
export -f resolve_domain

# ── Core: scan all ports for a single target ──────────────────────────────────

scan_target() {
  local target="$1"
  local ports_csv="$2"

  # Shared file paths are passed as env vars (exported below)
  IFS=',' read -ra ports <<< "$ports_csv"

  # Resolve target to IP(s)
  if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    local ips=("$target")
  else
    mapfile -t ips < <(resolve_domain "$target")
  fi

  if [[ ${#ips[@]} -eq 0 ]]; then
    safe_append "$target" "$FILE_NORESOLVE"
    return
  fi

  for ip in "${ips[@]}"; do
    local result="" open_found=false

    for port in "${ports[@]}"; do
      if nc -z -w1 "$ip" "$port" 2>/dev/null; then
        result+=" ${port}✔"
        open_found=true
      else
        result+=" ${port}✖"
      fi
    done

    if $open_found; then
      safe_append "$target -> $ip ->$result" "$FILE_OK"
    else
      safe_append "$target -> $ip ->$result" "$FILE_FAIL"
    fi
  done
}
export -f scan_target
export FILE_OK FILE_FAIL FILE_NORESOLVE

# ── Run ───────────────────────────────────────────────────────────────────────

PORTS_CSV=$(IFS=','; echo "${PORTS[*]}")
TOTAL=$(grep -c . "$TARGET_FILE" || true)

echo "Scanning $TOTAL target(s) across ${#PORTS[@]} ports — $PARALLEL_JOBS parallel jobs"
echo ""

parallel \
  --bar \
  --jobs "$PARALLEL_JOBS" \
  --line-buffer \
  scan_target {} "$PORTS_CSV" \
  :::: <(grep -v '^$' "$TARGET_FILE")

# ── Results ───────────────────────────────────────────────────────────────────

print_section() {
  local title="$1"
  local file="$2"
  echo ""
  echo "=== $title ==="
  if [[ -s "$file" ]]; then sort "$file"; else echo "(none)"; fi
}

print_section "OK — at least one port open" "$FILE_OK"
print_section "FAIL — all ports closed"     "$FILE_FAIL"
print_section "RESOLVE FAILED"              "$FILE_NORESOLVE"

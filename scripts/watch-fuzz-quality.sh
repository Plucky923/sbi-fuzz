#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <run_dir> [process_match]" >&2
  exit 2
fi

run_dir=$1
process_match=${2:-$run_dir}
csv_path="$run_dir/fuzz.csv"
result_dir="$run_dir/result"
log_path="$run_dir/watchdog.log"

interval_secs=${WATCHDOG_INTERVAL_SECS:-30}
warmup_secs=${WATCHDOG_WARMUP_SECS:-90}
min_total_results=${WATCHDOG_MIN_TOTAL_RESULTS:-500}
max_unknown_ratio=${WATCHDOG_MAX_UNKNOWN_RATIO:-0.05}

timestamp() {
  date '+%Y-%m-%d %H:%M:%S'
}

log() {
  printf '[%s] %s\n' "$(timestamp)" "$*" | tee -a "$log_path"
}

parse_global_csv() {
  python3 - "$csv_path" <<'PY'
import csv
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("missing")
    raise SystemExit(0)

latest = None
with path.open("r", encoding="utf-8", newline="") as fp:
    for row in csv.reader(fp):
        if row and row[0] == "GLOBAL":
            latest = row

if latest is None:
    print("missing")
    raise SystemExit(0)

runtime = latest[2]
clients = int(latest[3] or 0)
corpus = int(latest[4] or 0)
objectives = int(latest[5] or 0)
executions = int(latest[6] or 0)
edges = int(latest[8] or 0)
hh, mm, rest = runtime.split(":")
ss, ms = rest.split(".")
elapsed = int(hh) * 3600 + int(mm) * 60 + int(ss)
print(f"{elapsed} {clients} {corpus} {objectives} {executions} {edges}")
PY
}

count_results() {
  python3 - "$result_dir" <<'PY'
import sys
from pathlib import Path

result_dir = Path(sys.argv[1])
total = 0
unknown = 0
for path in result_dir.glob("*.toml"):
    total += 1
    if path.name.startswith("unknown-"):
        unknown += 1
print(f"{total} {unknown}")
PY
}

stop_fuzz() {
  log "quality regression detected; pausing fuzz processes matching: $process_match"
  pkill -STOP -f "$process_match" || true
}

log "watchdog started for $run_dir"

while true; do
  sleep "$interval_secs"

  read -r elapsed clients corpus objectives executions edges <<<"$(parse_global_csv)"
  if [ "$elapsed" = "missing" ]; then
    log "waiting for first GLOBAL csv row"
    continue
  fi

  read -r total_results unknown_results <<<"$(count_results)"
  unknown_ratio=$(python3 - <<PY
total = $total_results
unknown = $unknown_results
print(0.0 if total == 0 else unknown / total)
PY
)

  log "elapsed=${elapsed}s clients=$clients corpus=$corpus objectives=$objectives executions=$executions edges=$edges total_results=$total_results unknown_results=$unknown_results unknown_ratio=$unknown_ratio"

  if [ "$elapsed" -ge "$warmup_secs" ] && { [ "$corpus" -eq 0 ] || [ "$edges" -eq 0 ]; }; then
    log "regression: corpus/edges unhealthy after warmup"
    stop_fuzz
    exit 1
  fi

  if python3 - <<PY
total = $total_results
ratio = float("$unknown_ratio")
threshold_total = $min_total_results
threshold_ratio = float("$max_unknown_ratio")
raise SystemExit(0 if total >= threshold_total and ratio > threshold_ratio else 1)
PY
  then
    log "regression: unknown ratio exceeded threshold"
    stop_fuzz
    exit 1
  fi
done

#!/usr/bin/env bash
set -euo pipefail

ROOT="/mnt/sata4t/dir/PageAttack"
SUTURE_DIR="$ROOT/SUTURE/llvm_analysis"
PLUGIN="$SUTURE_DIR/MainAnalysisPasses/build_dir/SoundyAliasAnalysis/libSoundyAliasAnalysis.so"
Z3_LIBDIR="$SUTURE_DIR/MainAnalysisPasses/z3/bin"
OPT_BIN="/usr/lib/llvm-15/bin/opt"
TARGET_DIR="$ROOT/linux-6.17/drivers/spi"
BC_FILE="$TARGET_DIR/spidev.bc"
CONF_FILE="$TARGET_DIR/conf_spidev"
WARN_FILE="$TARGET_DIR/conf_spidev.warn.json"
INSTR_WARN_FILE="$TARGET_DIR/conf_spidev.iwarn.json"
STDOUT_FILE="$TARGET_DIR/conf_spidev.stdout"
STDERR_FILE="$TARGET_DIR/conf_spidev.stderr"

for path in "$PLUGIN" "$OPT_BIN" "$BC_FILE" "$CONF_FILE"; do
  if [[ ! -e "$path" ]]; then
    echo "missing required path: $path" >&2
    exit 1
  fi
done

rm -f "$WARN_FILE" "$INSTR_WARN_FILE" "$STDOUT_FILE" "$STDERR_FILE"

cd "$TARGET_DIR"
LD_LIBRARY_PATH="$Z3_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$OPT_BIN" \
  -enable-new-pm=0 \
  -load "$PLUGIN" \
  -dr_checker \
  -entryConfig="$(basename "$CONF_FILE")" \
  -outputFile="$(basename "$WARN_FILE")" \
  -instrWarnings="$(basename "$INSTR_WARN_FILE")" \
  "$(basename "$BC_FILE")" \
  -o /dev/null \
  >"$(basename "$STDOUT_FILE")" \
  2>"$(basename "$STDERR_FILE")"

python3 - <<'PY'
import json
from pathlib import Path

base = Path("/mnt/sata4t/dir/PageAttack/linux-6.17/drivers/spi")
warn = json.load(open(base / "conf_spidev.warn.json"))
instr = json.load(open(base / "conf_spidev.iwarn.json"))
print(f"warn contexts: {warn.get('num_contexts')}")
contexts = warn.get("all_contexts", [])
if contexts:
    print(f"warnings in first context: {contexts[0].get('num_warnings')}")
print(f"instr output top-level keys: {len(instr) if isinstance(instr, dict) else 'n/a'}")
PY

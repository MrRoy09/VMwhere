#!/usr/bin/env bash
set -euo pipefail

# install hyperfine if missing
if ! command -v hyperfine >/dev/null 2>&1; then
  . /etc/os-release
  case "$ID" in
    debian|ubuntu)
      sudo apt update
      sudo apt install -y hyperfine
      ;;
    arch)
      sudo pacman -Sy --noconfirm hyperfine
      ;;
    *)
      echo "Unsupported platform: $ID" >&2
      exit 1
      ;;
  esac
fi

# color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

BUILD_DIR=./build
NUM_TESTS=1000

orig_sum=0
obf_sum=0

echo "[INFO] Benchmarking $NUM_TESTS random inputs (max len=16)"

for i in $(seq 1 $NUM_TESTS); do
  len=$((RANDOM % 16 + 1))
  inp=$(head -c 256 /dev/urandom \
        | tr -dc '[:alnum:]' \
        | head -c "$len")

  # run hyperfine with no shell wrapper, a few warmup runs, suppress warnings
  t1=$(hyperfine \
        --style none \
        --shell=none \
        --warmup 3 \
        --export-json /dev/stdout \
        --runs 3 \
        "$BUILD_DIR/original '$inp'" \
      2>/dev/null | jq '.results[0].mean')

  t2=$(hyperfine \
        --style none \
        --shell=none \
        --warmup 3 \
        --export-json /dev/stdout \
        --runs 3 \
        "$BUILD_DIR/obfuscated '$inp'" \
      2>/dev/null | jq '.results[0].mean')

  orig_sum=$(echo "$orig_sum + $t1" | bc -l)
  obf_sum=$(echo "$obf_sum + $t2" | bc -l)

  if (( i % 100 == 0 )); then
    echo -e "${GREEN}[OK] Completed $i/$NUM_TESTS${NC}"
  fi
done

avg_orig=$(echo "scale=6; $orig_sum / $NUM_TESTS" | bc -l)
avg_obf=$(echo "scale=6; $obf_sum  / $NUM_TESTS" | bc -l)
slowdown=$(echo "scale=2; $avg_obf / $avg_orig" | bc -l)

echo
echo "=== RESULTS ==="
echo -e "${BLUE}avg original:   ${avg_orig}s${NC}"
echo -e "${BLUE}avg obfuscated: ${avg_obf}s${NC}"
echo -e "${YELLOW}slowdown factor: ${slowdown}x${NC}"

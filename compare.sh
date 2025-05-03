#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

BUILD_DIR=./build
NUM_TESTS=1000

for ((i=1; i<=NUM_TESTS; i++)); do
  len=$((RANDOM % 16 + 1))
  inp=$(head -c 256 /dev/urandom \
        | tr -dc '[:alnum:]' \
        | head -c "$len")

  out1=$("$BUILD_DIR/original" "$inp")
  out2=$("$BUILD_DIR/safe_main" "$inp")

  if [[ "$out1" != "$out2" ]]; then
    echo -e "${RED}[FAIL] Test Failed${NC}"
    echo -e "${RED}Mismatch on test #$i, input='$inp'${NC}"
    echo -e "${YELLOW}original:   <${out1}>${NC}"
    echo -e "${YELLOW}safe_main: <${out2}>${NC}"
    exit 1
  fi

  if (( i % 100 == 0 )); then
    echo -e "${GREEN} [ OK ] $i / $NUM_TESTS tests${NC}"
  fi
done


#!/bin/bash


if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <pass_source.c> <plugin_output.so> <output_executable>"
    exit 1
fi

PASS_SRC=$1
PLUGIN_SO="../passes/$2"
TARGET_SRC="../test/main.c"
OUTPUT_BIN="../test/$3"

mkdir -p ../passes
mkdir -p ../test

echo "[*] Building LLVM pass plugin..."
clang -fPIC -shared "$PASS_SRC" -o "$PLUGIN_SO" `llvm-config --cxxflags --ldflags --system-libs --libs core passes` || {
    echo "[!] Failed to compile pass plugin."
    exit 1
}

echo "[*] Compiling target with plugin..."
clang -c -fpass-plugin="$PLUGIN_SO" "$TARGET_SRC" -o "$OUTPUT_BIN" || {
    echo "[!] Failed to compile target with pass plugin."
    exit 1
}

echo "[+] Done. Output binary: $OUTPUT_BIN"
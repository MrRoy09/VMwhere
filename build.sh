#!/bin/bash

echo "[+] Starting build"

docker rmi -f bc360 2>/dev/null || true
docker build -t bc360 .

mkdir -p out

docker create --name bc360_t bc360

docker cp bc360_t:/build .

docker rm bc360_t

echo "[+] Build successful at ./build"

#!/usr/bin/env bash

set -e

IMAGE="ghcr.io/tiiuae/unitree-go2-ntrip-client"

echo "--- Building ARM64 on remote-builder ---"
docker buildx use remote-builder
docker buildx build \
  --build-arg BUILDPLATFORM=linux/amd64 \
  --build-arg TARGETARCH=arm64 \
  -t ${IMAGE}:latest-arm64 \
  --push \
  .

echo "--- Building AMD64 on default builder ---"
docker buildx use default
docker buildx build \
  --build-arg BUILDPLATFORM=linux/amd64 \
  --build-arg TARGETARCH=amd64 \
  -t ${IMAGE}:latest-amd64 \
  --push \
  .

echo "--- Creating Manifest ---"
docker buildx imagetools create \
  -t ${IMAGE}:latest \
  ${IMAGE}:latest-arm64 \
  ${IMAGE}:latest-amd64

echo "--- Done! ---"

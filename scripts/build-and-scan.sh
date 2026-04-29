#!/usr/bin/env bash
# build-and-scan.sh — operator entry point for Castellum supply-chain pass.
# AC#1: trivy image scan with HIGH+CRITICAL gating, --ignore-unfixed.
# AC#2: emits the operator cosign verify command (sign step is left to the operator
#        who controls cosign.key; verify is documented as the gate).
# AC#3: relies on cyclonedx-maven-plugin output baked into the jar via mvn package.
set -euo pipefail
TAG="${1:-castellum:latest}"

echo "[1/4] docker build -> $TAG"
docker build -t "$TAG" .

echo "[2/4] trivy image scan (HIGH,CRITICAL --ignore-unfixed)"
trivy image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed "$TAG"

echo "[3/4] syft SBOM extraction"
syft "$TAG" -o cyclonedx-json > sbom-image.cdx.json

echo "[4/4] cosign signing/verification (operator-driven)"
cat <<EOF
Operator commands (run separately with appropriate keys):
  cosign sign --key cosign.key $TAG
  cosign verify --key cosign.pub $TAG
KMS-backed alternative:
  cosign sign --key awskms:///<arn> $TAG
  cosign verify --key awskms:///<arn> $TAG
EOF

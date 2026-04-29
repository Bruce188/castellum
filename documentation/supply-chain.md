# Supply Chain

## Overview

Castellum ships as a multi-stage Docker image. The supply-chain pipeline lives in `scripts/build-and-scan.sh` and emits a CycloneDX SBOM at the JVM-dependency level via `cyclonedx-maven-plugin` and at the container level via `syft`. Trivy gates the image on HIGH/CRITICAL CVEs. Cosign signing is an operator-driven step.

## Build pipeline

The script `scripts/build-and-scan.sh` performs four sequential steps:

```
[1/4] docker build -> <tag>
[2/4] trivy image scan (HIGH,CRITICAL --ignore-unfixed)
[3/4] syft SBOM extraction
[4/4] cosign signing/verification (operator-driven)
```

**Step 1 — Docker build.** Builds the multi-stage image from `Dockerfile` at repo root. The builder stage uses `maven:3.9-eclipse-temurin-21` to compile and package the application. The final stage copies the JAR into `gcr.io/distroless/java21-debian12:nonroot`.

**Step 2 — Trivy scan.** Runs `trivy image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed <tag>`. The `--exit-code 1` flag causes the script (and CI) to fail immediately if any HIGH or CRITICAL vulnerability has a known fix available. Unfixed CVEs are excluded from the gate to prevent false blocks on OS packages awaiting upstream patches.

**Step 3 — SBOM extraction.** Uses `syft` to produce an image-level CycloneDX SBOM at `sbom-image.cdx.json`. This complements the Maven-plugin SBOM (`target/bom.xml`, `target/bom.json`) which captures JVM dependencies resolved at build time.

**Step 4 — Cosign operator guidance.** The script emits the commands an operator needs to sign and verify the image. The script itself does not sign; signing requires the operator's private key. This deliberate separation keeps secret material out of automated build agents.

### Running the pipeline

```bash
# Build, scan, and generate SBOM for the default tag:
bash scripts/build-and-scan.sh

# Or specify a custom tag:
bash scripts/build-and-scan.sh castellum:v1.2.3
```

## Dockerfile rationale

### Multi-stage layout

```dockerfile
# syntax=docker/dockerfile:1.7
ARG DISTROLESS_VARIANT=nonroot

FROM maven:3.9-eclipse-temurin-21 AS build
# ... compile + package
FROM gcr.io/distroless/java21-debian12:${DISTROLESS_VARIANT}
COPY --from=build /castellum.jar /app/castellum.jar
USER nonroot
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/castellum.jar"]
```

The builder stage includes Maven, the JDK, and all build tooling. None of these tools appear in the final image. The final stage contains only the JRE runtime provided by the distroless image and the application JAR.

### Distroless choice

`gcr.io/distroless/java21-debian12` is a Google-maintained minimal Java 21 image with no shell, no package manager, and no OS utilities. This significantly reduces the attack surface compared to `eclipse-temurin:21-jre` or `amazoncorretto:21`. Known tradeoffs:

- No shell → `docker exec` interactive debugging requires the `:debug-nonroot` variant.
- Smaller CVE surface → Trivy scans produce fewer findings.
- Faster cold start is not guaranteed; JVM startup is dominant.

### `:nonroot` vs `:debug-nonroot`

| Variant | Shell | Use case |
|---------|-------|----------|
| `nonroot` (default) | No | Production |
| `debug-nonroot` | BusyBox sh | Incident triage inside a running container |

To build the debug variant for triage:

```bash
docker build --build-arg DISTROLESS_VARIANT=debug-nonroot -t castellum:debug .
docker run --rm -it --entrypoint /busybox/sh castellum:debug
```

## Operator runtime

### Recommended `docker run` invocation

```bash
docker run \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  -p 8080:8080 \
  -e CASTELLUM_SECURITY_JWT_SECRET="$(openssl rand -base64 48)" \
  -e CASTELLUM_ADMIN_USERNAME=admin \
  -e CASTELLUM_ADMIN_PASSWORD_HASH='$2a$12$...' \
  castellum:latest
```

`CAP_NET_RAW` is required by `pcap4j`, which is used by the passive discovery (PCAP) source. If you do not need PCAP discovery, you can drop this capability too.

Note: `HEALTHCHECK` is not baked into the image. Wire the `/actuator/health` endpoint externally via your orchestrator (Kubernetes liveness probe, Docker Compose `healthcheck`, ECS health check).

### Kubernetes example

```yaml
livenessProbe:
  httpGet:
    path: /actuator/health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /actuator/health
    port: 8080
  initialDelaySeconds: 15
  periodSeconds: 5
```

## Cosign procedure

### Key-pair signing

```bash
# Generate key pair (creates cosign.key and cosign.pub in cwd):
cosign generate-key-pair

# Sign the image (requires cosign.key):
cosign sign --key cosign.key castellum:latest

# Verify the signature (use cosign.pub in deployment verification):
cosign verify --key cosign.pub castellum:latest
```

Expected output from `cosign verify`:

```
Verification for index.docker.io/your-org/castellum:latest --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"..."},...}}]

Verified OK
```

### KMS-backed signing (recommended for production)

Replace the local key pair with a KMS-backed key to avoid storing `cosign.key` on disk:

```bash
# AWS KMS:
cosign sign --key awskms:///<key-arn> castellum:latest
cosign verify --key awskms:///<key-arn> castellum:latest

# GCP KMS:
cosign sign --key gcpkms://projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key> castellum:latest
cosign verify --key gcpkms://projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key> castellum:latest
```

## Trivy gating policy

The current policy:

```
--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1
```

- **`--severity HIGH,CRITICAL`** — gates only on serious CVEs. MEDIUM and LOW are reported but do not block.
- **`--ignore-unfixed`** — skips CVEs where no fixed version is available in the upstream package repository. This prevents blocking on OS-level CVEs that are known but not yet patched by Debian.
- **`--exit-code 1`** — non-zero exit causes CI to fail.

### Upgrade path

1. Once the distroless base image is updated faster than findings accumulate, remove `--ignore-unfixed` to enforce a stricter posture.
2. After achieving a clean HIGH/CRITICAL gate, add `MEDIUM` to the severity list.
3. Consider adding `--db-repository ghcr.io/aquasecurity/trivy-db` for reproducible CI scans.

## SBOM

Two SBOM artifacts are produced per release:

| Artifact | Tool | Scope | Format |
|----------|------|-------|--------|
| `target/bom.xml` | `cyclonedx-maven-plugin` 2.8.0 | JVM dependencies (compile + runtime) | CycloneDX 1.5 XML |
| `target/bom.json` | `cyclonedx-maven-plugin` 2.8.0 | JVM dependencies (compile + runtime) | CycloneDX 1.5 JSON |
| `sbom-image.cdx.json` | `syft` | Image-level (OS packages + JVM deps) | CycloneDX JSON |

The Maven plugin is bound to the `package` phase via `makeAggregateBom`. SBOM files are generated as part of every `mvn package` invocation, including CI.

## Explicit non-claims

Castellum does NOT claim SLSA-3, hermetic builds, or in-image cosign verify. The build pipeline is operator-run and relies on trust in the Maven Central dependency resolution. Hermetic builds and in-toto provenance attestations are deferred to a future iteration.

## Known limitations

- **Token revocation gap**: JWT TTL is 1 hour. Changing `CASTELLUM_SECURITY_JWT_SECRET` invalidates all in-flight tokens. There is no per-token blocklist (deferred item — requires a Redis or DB-backed blocklist and adds per-request overhead).
- **No hardware MFA**: Only password authentication is supported. FIDO2/WebAuthn is out of scope.
- **Rate limiting**: Login endpoint is not rate-limited. Brute-force protection is deferred.
- **Single-role tokens**: A user has exactly one role. Fine-grained scopes are not supported.

## AC#1 evidence procedure

```bash
# Build, scan, and confirm zero HIGH/CRITICAL fixable CVEs:
bash scripts/build-and-scan.sh
```

Expected output (abridged):

```
[1/4] docker build -> castellum:latest
...
[2/4] trivy image scan (HIGH,CRITICAL --ignore-unfixed)
2025-xx-xx INFO  Vulnerability scanning is enabled
2025-xx-xx INFO  Secret scanning is enabled
castellum:latest (debian 12.x)
====================================================
Total: 0 (HIGH: 0, CRITICAL: 0)

[3/4] syft SBOM extraction
...
[4/4] cosign signing/verification (operator-driven)
Operator commands (run separately with appropriate keys):
  cosign sign --key cosign.key castellum:latest
  cosign verify --key cosign.pub castellum:latest
```

## AC#2 evidence procedure

```bash
# After building the image:
cosign generate-key-pair
cosign sign --key cosign.key castellum:latest
cosign verify --key cosign.pub castellum:latest
```

Sample output excerpt:

```
Verified OK
```

## AC#3 evidence procedure

```bash
cd backend && ./mvnw -DskipTests=true package
ls target/bom.xml target/bom.json
```

Expected:

```
target/bom.xml
target/bom.json
```

Both files are CycloneDX 1.5 format. The XML file can be validated against the CycloneDX schema at `https://cyclonedx.org/schema/bom-1.5.xsd`.

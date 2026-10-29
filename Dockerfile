# syntax=docker/dockerfile:1.7

# Base images are digest-pinned (tag@sha256:index-digest) for reproducible builds.
# Refresh a digest with:
#   curl -sI -H "Authorization: Bearer $(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/<repo>:pull" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')" -H "Accept: application/vnd.oci.image.index.v1+json" https://registry-1.docker.io/v2/library/<repo>/manifests/<tag> | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}'

# Stage 1 (web): build the React SPA so the backend can serve it same-origin.
FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS web
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2 (build): compile the Spring Boot jar with the SPA embedded as static content.
FROM maven:3.9-eclipse-temurin-21@sha256:d7e7f57407437c014571f1ad5a9955f03fc3edcb1d964067ef351fa38e798665 AS build
WORKDIR /src
COPY backend/pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -B dependency:go-offline
COPY backend/src ./src
# Embed the built SPA into the Maven module BEFORE packaging so Spring serves it from
# classpath:/static/ (same-origin, single image: API under /api, dashboard at /).
COPY --from=web /app/frontend/dist/ ./src/main/resources/static/
# Tests run separately in CI (mvn test) before image build; skip here to keep the builder lean.
RUN --mount=type=cache,target=/root/.m2 mvn -B -DskipTests package
RUN cp target/backend-*.jar /castellum.jar

# Stage 3 (runtime): JRE + nmap + libpcap so active scanning and passive discovery work.
#
# Trade-off vs distroless: the previous runtime (gcr.io/distroless/java21) has no shell and
# no apt, so it could neither ship nmap/libpcap nor install them — the scanner and pcap4j
# were dead in the packaged image. Moving to a JRE+apt base restores that functionality at
# the cost of a larger attack surface (shell, apt, extra packages). Kept deliberately minimal:
# --no-install-recommends, apt lists dropped, non-root user, file caps scoped to nmap only.
FROM eclipse-temurin:21-jre-noble@sha256:5ea5c6c4c4f75be58b4391e91b14f72f53c3e7e43a304d537ceecd3f5513260d
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap libpcap0.8 libcap2-bin ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (matches the distroless uid 65532 the image previously ran as).
RUN useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin app

COPY --from=build /castellum.jar /app/castellum.jar

# Grant raw-socket caps on the nmap binary itself. A non-root uid needs file capabilities to
# run nmap -sn/-O/-sS; a runtime --cap-add=NET_RAW alone is NOT sufficient without them.
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

USER app
EXPOSE 8080
# No HEALTHCHECK: temurin-noble ships no curl/wget; health-checking is left to the orchestrator.
ENTRYPOINT ["java","-jar","/app/castellum.jar"]

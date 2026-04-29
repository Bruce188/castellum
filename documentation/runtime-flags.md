# Runtime Flags & Native Dependencies

<!-- TODO(feature-9): wire JVM flags into ENTRYPOINT java; resolve distroless caveat. -->

This document is the single source of truth for the pcap4j runtime requirements introduced in feature 4 (`feat/passive-discovery`). Feature 9 (`feat/security-hardening-and-supply-chain`) will read from this file when wiring the production Dockerfile.

## 1. JVM flags

The pcap4j 1.8.x library uses JNA to call into the native `libpcap.so` library. JNA reflectively accesses internals of `sun.nio.ch` and triggers JDK 21's restricted-native-access guard. Two JVM flags are required:

- `--enable-native-access=ALL-UNNAMED`
- `--add-opens java.base/sun.nio.ch=ALL-UNNAMED`

These flags are wired in **Maven Surefire** (`backend/pom.xml` → `<build><plugins>` → `maven-surefire-plugin` → `<argLine>`) so tests run with the same flag set as production.

When feature 9 lands the production Dockerfile, the `ENTRYPOINT java` line MUST include both flags. Example:

```dockerfile
ENTRYPOINT ["java", \
  "--enable-native-access=ALL-UNNAMED", \
  "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED", \
  "-jar", "/app/backend.jar"]
```

## 2. Linux capability

The PCAP source (`PcapSniffer`) opens raw sockets via libpcap. Raw-socket open requires the `CAP_NET_RAW` Linux capability.

The production container MUST run with `CAP_NET_RAW` and **all other capabilities dropped**. Example Docker run:

```bash
docker run --cap-drop=ALL --cap-add=NET_RAW castellum:latest
```

Equivalent Kubernetes `securityContext`:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_RAW"]
```

The ARP and MDNS sources do NOT require `CAP_NET_RAW`. ARP reads `/proc/net/arp` (filesystem only). MDNS uses the JVM's standard multicast socket.

## 3. Native library

`libpcap.so` (Linux package: `libpcap0.8`, version >= 1.0.0). NOT a Maven dependency — provided by the host OS or container layer.

On Debian/Ubuntu: `apt-get install libpcap0.8`.

## 4. Distroless caveat

> [!WARNING]
> `gcr.io/distroless/java21:nonroot` does NOT ship `libpcap.so`. The PCAP source will fail at runtime under distroless.

This is **a feature-9 architectural decision flagged by feature 4**. Three options:

(a) **Drop distroless app-wide** for `gcr.io/distroless/java21-debian12:nonroot` plus a `RUN apt-get install libpcap0.8` layer (requires switching from the pure distroless to a Debian-slim base for the whole app).

(b) **Ship a separate `castellum-discovery` image** based on `debian:slim` with `libpcap0.8` preinstalled, while the rest of the app stays distroless. Two images, one shared codebase.

(c) **Document discovery as host-deployment-only** (no Docker support for the discovery feature). PCAP source returns a structured "discovery_unavailable" error in containerized deployments.

Option (a) is the recommended default but trades distroless's minimal-attack-surface advantage. Option (b) preserves distroless for the rest of the app at the cost of operational complexity. Option (c) preserves distroless cleanly but degrades the feature in production. Decision pending — feature 9.

## 5. Linux-only contract for v1

`/proc/net/arp` does not exist on Windows or macOS. The `ArpCacheReader` returns an empty list when the file is absent (no exception). Future ports could read:
- Windows: `GetIpNetTable` via JNA.
- macOS: `/Library/Preferences/SystemConfiguration/...` plus `arp -an` parsing (sysctl-based).

Both ports are out of scope for v1. README documents the Linux-only contract operationally.

## 6. setcap alternative for non-Docker deployments

For systemd or bare-metal deployments where Docker capability dropping is not available, `setcap` on a Java wrapper script grants `CAP_NET_RAW` without root:

```bash
sudo setcap cap_net_raw+eip /usr/local/bin/castellum-launcher
```

Caveat: `setcap` on the JDK binary itself is brittle — `java` binary updates wipe the capability. Prefer `setcap` on a wrapper script that exec's the real `java`.

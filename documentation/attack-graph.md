# Attack Graph

The attack graph models lateral-movement and exploitation paths between known devices. It is built on demand from the device + service + CVE corpus, scored with the composite risk model (CVSS x EPSS x KEV x criticality), and queried via the REST API. The graph layer is read-only with respect to persistent state — it builds an in-memory `org.jgrapht.Graph<DeviceVertex, AttackEdge>` per request and discards it once the response is rendered.

## Endpoint

```
GET /api/graph/shortest-path?from=<device-id>&to=<device-id>
Authorization: Bearer <jwt>
```

Required role: `VIEWER` or `ADMIN`. Both `from` and `to` must be positive longs and must differ. Validation is enforced server-side in `GraphService.shortestPath`; the controller defers to the service.

Response shape (200 OK):

```json
{
  "from": 1,
  "to": 7,
  "hops": [
    {
      "deviceId": 1,
      "ipAddress": "10.0.0.10",
      "edgeType": null,
      "attackTechniqueId": null,
      "attackTechniqueName": null,
      "edgeRisk": 0.00,
      "cumulativeRisk": 0.00,
      "cveId": null
    },
    {
      "deviceId": 7,
      "ipAddress": "10.0.0.42",
      "edgeType": "EXPLOITABLE_VULN",
      "attackTechniqueId": "T1210",
      "attackTechniqueName": "Exploitation of Remote Services",
      "edgeRisk": 8.50,
      "cumulativeRisk": 8.50,
      "cveId": "CVE-2020-15778"
    }
  ],
  "totalHops": 1,
  "cumulativeRisk": 8.50,
  "pathFound": true
}
```

The first entry in `hops` is always the source vertex with `edgeType=null` — subsequent entries describe one inbound edge each. `totalHops` equals `hops.length - 1`. When no path exists, `pathFound=false`, `hops=[]`, `totalHops=0`, `cumulativeRisk=0.00`.

Error mapping:

| Condition | HTTP status | Body |
| --------- | ----------- | ---- |
| `from <= 0`, `to <= 0`, or `from == to` | 400 | `{"error": "...", "details": []}` |
| Either device not present | 404 | `{"error": "Not found", "details": []}` |
| Device count exceeds `castellum.graph.max-devices` | 503 | `{"error": "GRAPH_TOO_LARGE", "message": "..."}` |

## Edge types and ATT&CK technique mapping

Each edge carries an `EdgeType` and a captured ATT&CK technique id (recorded at edge build time so the response cannot drift from the producer's mapping decision). Technique names are stable and align with the MITRE ATT&CK Enterprise framework.

| EdgeType | Default technique | Service-aware override |
| -------- | ----------------- | ---------------------- |
| `SAME_SUBNET` | T1021 Remote Services | — |
| `EXPLOITABLE_VULN` | T1190 Exploit Public-Facing Application | T1210 Exploitation of Remote Services when service name contains `smb`, `rpc`, `rdp`, or `ssh` (case-insensitive, `Locale.ROOT`) |
| `WEAK_CRED_PATH` | T1078 Valid Accounts | — (typed-but-empty seam in v1; no signal source wired) |

The service-aware refinement runs at `GraphBuilder.build()` time and is captured in `AttackEdge.techniqueId`. `GraphService.shortestPath` reads the per-edge technique id directly rather than re-mapping by `EdgeType` — this avoids a re-mapping seam and ensures the response reflects the producer's classification.

## Edge weight and risk-contribution model

Two parallel scalars are tracked per edge:

- **Weight** — Dijkstra cost. Lower means a more attractive lateral-movement step.
- **Risk contribution** — defender-pain dual of the weight. Higher means a worse compromise.

The two diverge intentionally: Dijkstra prefers low-effort traversal, while risk reporting prefers high-impact edges.

| EdgeType | Weight | Risk contribution |
| -------- | ------ | ----------------- |
| `SAME_SUBNET` | `1.0` | `0.0` |
| `EXPLOITABLE_VULN` | `11.0 - composite_score` (range `[1.0, 11.0]`) | `composite_score` (range `[0.0, 10.0]`) |
| `WEAK_CRED_PATH` | `2.0` | `5.0` |

The `EXPLOITABLE_VULN` weight inversion (`11.0 - composite_score`) is strictly positive (composite is bounded in `[0, 10]`) and ensures higher-severity CVEs produce lower-cost edges in Dijkstra. The risk contribution preserves the composite score directly so the response's `cumulativeRisk` aggregates defender pain across the path.

`WEAK_CRED_PATH` has no signal source in v1; the type is reserved for future credential-graph integration.

## Composite score

The composite score is computed by `io.castellum.risk.CompositeScorer` from CVSS, EPSS, KEV, and the target device's `Criticality`. Scoring is memoized per build via `CompositeScoreMemoizer` keyed on `(cveId, deviceId)` — two same-subnet peers routing through the same target device + CVE pair share a single repository read. Two different target devices for the same CVE do NOT share the cache, because the composite incorporates target criticality.

## Performance bounds

Three guards prevent unbounded graph builds:

| Property | Default | Behaviour when exceeded |
| -------- | ------- | ----------------------- |
| `castellum.graph.subnet-cap` | 64 | Group is logged at WARN and **skipped**; no SAME_SUBNET edges emitted for that bucket. |
| `castellum.graph.vulns-per-pair-cap` | 5 | Top-N vulnerabilities (by composite score, descending) are retained per device pair. |
| `castellum.graph.max-devices` | 1024 | Build throws `GraphTooLargeException`; `GlobalExceptionHandler` maps to HTTP 503 with `error="GRAPH_TOO_LARGE"`. |

All three are tunable via env (`GRAPH_SUBNET_CAP`, `GRAPH_VULNS_PER_PAIR_CAP`, `GRAPH_MAX_DEVICES`) or via the Spring config-properties prefix `castellum.graph.*`.

## Multi-edge dedupe contract

The graph is a `DirectedWeightedPseudograph<DeviceVertex, AttackEdge>` — JGraphT permits **parallel edges** between the same vertex pair. The builder dedupes structurally via the JGraphT `Graph#addEdge(src, dst, edge)` return value: a `false` return means the edge was rejected as a duplicate of an existing `AttackEdge` instance.

- `SAME_SUBNET` edges have a null `cveId` and naturally collapse to one edge per direction.
- `EXPLOITABLE_VULN` edges are bounded by `vulnsPerPairCap`. Up to N parallel `EXPLOITABLE_VULN` edges may coexist between the same vertex pair, one per CVE.

UI consumers (e.g. the Cytoscape-based topology view in the frontend) MUST further dedupe presentation if they collapse the parallel edges into a single visual indicator. The shortest-path response returns one hop per edge in the path; multi-edge collapsing is a presentation concern only.

## Subnet bucketing — IPv4 and IPv6

The SAME_SUBNET pass groups devices by network prefix:

- **IPv4** — /24 prefix (first three octets). Bucket key format: `v4:a.b.c`.
- **IPv6** — /64 prefix (first eight bytes). Bucket key format: `v6:h:h:h:h` (colon-separated hextets, lowercase).

Both families share a single `Map<String, List<Device>>` keyed on the prefixed bucket key, so an IPv4 group and an IPv6 group never collide. Devices whose `ip_address` field fails to parse (`InetAddress.getByName` raises `UnknownHostException`) or returns an unexpected `InetAddress` family are silently skipped from subnet grouping; no SAME_SUBNET edges originate from such devices.

This widens the v1 IPv4-only behaviour. The /64 boundary aligns with the de facto IPv6 LAN allocation; /127 point-to-point links and ULAs both operate within this granularity.

## Vertex lookup

`BuiltGraph.vertexById()` returns an `O(1)` `Map<Long, DeviceVertex>` populated during build. `GraphService.shortestPath` uses this map for both `from` and `to` lookups instead of walking the vertex set. The map is unmodifiable (constructed via `Map.copyOf`) — callers cannot mutate it.

## Acceptance test note

The `AcceptanceSmokeTest.ac1_shortestPathReturnsOrderedHopsWithCumulativeRisk` fixture seeds three devices in `10.0.0.0/24` with an OpenSSH-on-d3 + CVE-2020-15778-AC1 vulnerability and asserts the shortest-path response has the expected structural integrity (every non-source hop carries an `edgeType` and `attackTechniqueId`). A strict assertion that the path traverse an `EXPLOITABLE_VULN` hop is **not** enforceable in the current model: SAME_SUBNET weight (1.0) is the floor, and EXPLOITABLE_VULN weight is bounded `[1.0, 11.0]`, so Dijkstra prefers same-subnet traversal whenever both endpoints share a /24. Cross-subnet vuln edges are out of v1 scope (analysis-v15 D1 Option S, deferred).

## Audit semantics

`GraphService.shortestPath` does NOT emit an audit-log entry. The `auditService` constructor seam is preserved for future re-introduction, but the per-query `GRAPH_QUERY` event was dropped in feature 5 to align with the analysis-v5 OQ#7 decision (read-only queries do not produce audit rows by default).

## Implementation surface

| Class | Responsibility |
| ----- | -------------- |
| `GraphBuilder` | Build the graph from `Device`, `NetworkService`, `Cve` corpora; emit SAME_SUBNET and EXPLOITABLE_VULN edges; enforce caps. |
| `BuiltGraph` | Immutable record holding the JGraphT graph + `vertexById` map. |
| `GraphService` | Validate input, lookup vertices, invoke `ShortestPathFinder`, render `ShortestPathResponse`. |
| `ShortestPathFinder` | Wraps `org.jgrapht.alg.shortestpath.DijkstraShortestPath`. |
| `EdgeWeights` | Pure static utility — weight and risk-contribution functions. |
| `CpeMapper` | Lossy `NetworkService` → CPE 2.3 string (`vendor=product=lowercase-sanitized(name)`). |
| `CompositeScoreMemoizer` | Per-build cache of `CompositeScorer` outputs keyed on `(cveId, deviceId)`. |
| `AttackTechniqueMapper` | `EdgeType` → ATT&CK technique mapping with service-aware overload. |
| `AttackEdge` | JGraphT `DefaultWeightedEdge` subclass with `EdgeType`, `riskContribution`, `cveId`, `techniqueId`. |
| `GraphProperties` | Spring `@ConfigurationProperties(prefix = "castellum.graph")` — caps, defaults. |
| `GraphTooLargeException` | Thrown on `max-devices` overflow; mapped to HTTP 503. |
| `GraphController` | REST endpoint `GET /api/graph/shortest-path`. |

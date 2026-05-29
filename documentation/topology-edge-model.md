# Topology Edge Model and Docker-Network Zoning

This document describes how Castellum's topology renderer models edges between
devices, with particular focus on Docker-scoped devices and the pivot (docker-host)
edge routing introduced in the `feat/topology-edge-model-and-docker-zone` feature.

## Edge kinds

The frontend derives edges client-side in `src/lib/gatewayEdges.ts`. Three edge
kinds exist:

| Kind | Description |
|---|---|
| `gateway` | Default subnet-star edge. Lowest-IP device in a `/24` becomes the gateway; all other devices in that subnet edge to it. |
| `isolated` | Device in a singleton `/24` (no peers). A self-referencing stub edge so the node is not orphaned in the graph. |
| `docker-bridge` | Synthetic cross-zone edge produced for devices with `discoveryScope = DOCKER_BRIDGE`. Routing depends on `publishesHostPort` (see below). |

## Docker pivot edge routing

The "pivot" is the docker host: the `HOME`-scoped device whose IP matches the
topology's configured docker-host IP (default: the lowest `HOME` IP; overridable
via `localStorage["castellum.topology.docker-host-ip"]`).

Docker-bridge edge routing follows three rules applied in order:

1. **Docker-net gateway nodes** (`isDockerNetGateway` — hostname matches
   `docker-net:<name>`) edge directly from the pivot to the gateway node.
2. **Published-port containers** (`publishesHostPort === true`) edge directly from
   the pivot to the container.
3. **Internal-only containers** (`publishesHostPort === false`, not a gateway)
   edge from the container to its network's docker-net gateway (resolved by
   matching the container's `/24` to the gateway's `/24`). If no docker-net
   gateway exists for that `/24`, the container falls back to a direct pivot edge
   to avoid being orphaned.

This keeps the pivot's fan-out bounded: the number of pivot-incident edges is
`(published containers) + (distinct docker networks)`, not `(all containers)`.

### Visual summary

```
pivot (HOME)
  ├── docker-bridge ──► docker-net:net_a  (gateway, DOCKER_BRIDGE)
  │                         ▲
  │                         └── docker-bridge ── internal-container-1
  │                         └── docker-bridge ── internal-container-2
  ├── docker-bridge ──► published-container-A  (DOCKER_BRIDGE, publishesHostPort=true)
  └── docker-bridge ──► published-container-B  (DOCKER_BRIDGE, publishesHostPort=true)
```

## DOCKER_BRIDGE gateway zoning

Docker-net gateway devices are assigned `DiscoveryScope.DOCKER_BRIDGE` (not
`HOME`) by `DockerDiscoveryService`. This ensures `scopeToZoneId` maps them to
`zone-docker`, placing them visually inside the Docker zone rather than the Home
zone. Gateways always have `publishesHostPort = false`.

## `publishesHostPort` device field

### Backend

The `device` table gains a boolean column added by Flyway migration **V24**:

```sql
ALTER TABLE device ADD COLUMN publishes_host_port BOOLEAN NOT NULL DEFAULT FALSE;
```

The `Device` entity exposes `isPublishesHostPort()` / `setPublishesHostPort(boolean)`.

`DockerDiscoveryService` sets this field to `true` when Docker reports that the
container binds at least one port to `0.0.0.0` or a specific host interface.
Gateway entries and all non-Docker devices always receive `false`.

### API exposure

`GET /api/devices` (paginated list) serialises `publishesHostPort` in every device
object. A device with the flag set produces:

```json
{
  "id": 42,
  "ipAddress": "172.18.0.5",
  "discoveryScope": "DOCKER_BRIDGE",
  "publishesHostPort": true,
  ...
}
```

### Frontend type

`src/api/types.ts` declares the field on the `Device` interface:

```typescript
/**
 * True when this DOCKER_BRIDGE container publishes at least one host port.
 * False for internal-only containers and all non-DOCKER_BRIDGE devices.
 */
publishesHostPort: boolean;
```

## Unattached Docker group rendering

`buildDockerNetworkGroups` (`src/lib/dockerNetworkGroups.ts`) produces one
`DockerNetworkGroup` per active docker network (named, `muted: false`) plus an
optional fallback group for stale / unattached devices — ARP residue with no
running container or docker-net gateway (`muted: true`).

`TopologyView` uses the `muted` flag to assign the CSS class `muted-group` to the
Cytoscape compound node, applying:

- `opacity: 0.45`
- dashed border in `#9ca3af`
- grey label text

This visually distinguishes stale residue from live network groups without
removing the nodes from the graph.

## Source files

| File | Role |
|---|---|
| `backend/.../V24__device_publishes_host_port.sql` | Flyway migration adding the column |
| `backend/.../domain/Device.java` | Entity field + accessors |
| `backend/.../discovery/DockerDiscoveryService.java` | Sets `publishesHostPort` and assigns `DOCKER_BRIDGE` scope to gateways |
| `backend/.../discovery/DeviceUpsertService.java` | Persists `publishesHostPort` via `upsertWithScope` |
| `frontend/src/api/types.ts` | `Device.publishesHostPort` wire type |
| `frontend/src/lib/gatewayEdges.ts` | Docker pivot edge routing logic |
| `frontend/src/lib/dockerNetworkGroups.ts` | `DockerNetworkGroup.muted` flag + unattached group |
| `frontend/src/components/TopologyView.tsx` | Muted-group stylesheet + class assignment |

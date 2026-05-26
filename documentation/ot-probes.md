# OT/ICS Read-Only Fingerprinters

Castellum can passively fingerprint OT/ICS (Operational Technology / Industrial Control System)
devices using read-only protocol requests. No write commands are ever issued; every probe PDU uses
only read-classified function codes.

## Supported Protocols

| Protocol | Port | Transport | Read-only mechanism |
|----------|------|-----------|---------------------|
| Modbus/TCP | 502 | TCP | FC 0x2B MEI 0x0E (Read Device Identification) |
| DNP3 | 20000 | TCP | FC 0x01 READ, g0v254 (All Device Attributes) |
| S7comm | 102 | TCP | TPKT/COTP/S7 SZL 0x0011 (Module Identification) |
| BACnet/IP | 47808 | UDP | BVLL Who-Is unicast + ReadProperty (SVC 0x0C) |

## REST Endpoint

```
POST /api/ot-probe
Content-Type: application/json

{
  "host":     "192.168.1.10",   -- IPv4 only, no hostnames (SSRF guard)
  "port":     502,
  "protocol": "MODBUS_TCP"      -- MODBUS_TCP | DNP3 | S7COMM | BACNET_IP
}
```

### Success response (HTTP 200)

```json
{
  "host":       "192.168.1.10",
  "port":       502,
  "protocol":   "MODBUS_TCP",
  "vendor":     "Schneider Electric",
  "product":    "Modicon M340",
  "version":    "V2.40",
  "rawFields":  { "0": "Schneider Electric", "1": "Modicon M340", "2": "V2.40" },
  "deviceId":   7,
  "serviceId":  12,
  "observedAt": "2026-04-29T08:15:00Z"
}
```

`rawFields` keys are the string representations of Modbus object IDs / DNP3 attribute numbers /
S7 SZL fields / BACnet property IDs, depending on the protocol.

### Error responses

| HTTP | Condition |
|------|-----------|
| 400 | Invalid request body (missing fields, bad port range, hostname instead of IP, unknown protocol) |
| 404 | (reserved for device-lookup errors in future wiring) |
| 501 | Protocol not yet implemented |
| 502 | Device unreachable or malformed protocol response |
| 503 | Concurrency limit reached (all probe slots occupied) |
| 504 | Probe timed out |

## SSRF Guard

`host` is validated with `HostValidator.requireValid()` before any network I/O:

- Must be a dotted-quad IPv4 address (no hostnames, no IPv6).
- Multicast (224.0.0.0/4) and broadcast (255.255.255.255) are rejected.
- The address is resolved with `InetAddress.getByAddress(byte[])` — no DNS lookup occurs.

## Protocol Notes

### Modbus/TCP — FC 0x2B MEI 0x0E

Sends a Modbus Read Device Identification request for the Basic device id group. Parses object IDs
0x00 (vendor name), 0x01 (product code), 0x02 (firmware revision). The request is exactly 11 bytes;
no write function codes (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17) are ever emitted.

### DNP3

Sends a DNP3 READ request for Group 0 Variation 254 (All Device Attributes) over TCP. The data-link
frame and data block carry CRC-16/DNP checksums (polynomial 0xA6BC reflected, init=0, xorout=0xFFFF;
check value for "123456789" = 0xEA82). Forbidden function codes (WRITE 0x02, DIRECT_OPERATE 0x03,
DIRECT_OPERATE_NR 0x04, FREEZE 0x07, FREEZE_CLEAR 0x08, etc.) are never used.

### S7comm

Sends TPKT/COTP/S7 PDUs in three steps:

1. COTP Connection Request (CR)
2. S7 Setup Communication (FN 0xF0)
3. S7 CPU Services — Read SZL 0x0011 (Module Identification)

The SZL read is a CPU service request (FN 0x00). No write/download functions (FN 0x05, 0x1A, 0x1B,
0x1C, 0x1D, 0x28, 0x29, 0x46) are sent. The response SZL block provides manufacturer code,
ordering number, and firmware version. Manufacturer code 0x002A and 0x0042 are resolved to "Siemens".

### BACnet/IP

Sends two UDP datagrams to the target unicast address:

1. BVLL Who-Is (Unconfirmed-Service-Request, SVC 0x08) — discovers the device instance.
2. BACnet ReadProperty (Confirmed-Service-Request, SVC 0x0C = decimal 12) — reads vendor-name and
   model-name properties of the device object.

Note: SVC 0x0C = decimal 12 = ReadProperty. Do not confuse with 0x0E hex (= decimal 14 =
CreateObject), which is a write-classified service and is never used.

## Passive discovery endpoints

`POST /api/ot-probe` covers the active read-only fingerprint. The complementary passive-
discovery surface is exposed under `/api/discovery`:

| Method + path | Role | Behaviour |
|---------------|------|-----------|
| `POST /api/discovery/passive` | ADMIN | Run a one-shot passive sweep on the given interface using the requested sources (ARP, MDNS, PCAP, LLDP, CDP). Returns a `PassiveDiscoveryResponse` with `discovered` count, per-source breakdown, upserted device ids, and a `sweepId`. |
| `GET /api/discovery/sources` | VIEWER, ADMIN | Reports the configured availability of each discovery source (ARP and MDNS always enabled; PCAP/LLDP/CDP gated by `castellum.discovery.{pcap,lldp,cdp}.enabled`). |
| `GET /api/discovery/interfaces` | ADMIN | Lists the host's up, non-loopback network interfaces — the menu of choices for the `iface` field on the sweep endpoint. Returns `InterfaceInfoDto[]` (`{name, displayName, mtu}`). Best-effort enumeration: an empty list is returned (never null) if `NetworkInterface.getNetworkInterfaces()` throws or yields no qualifying interfaces. |
| `GET /api/discovery/sweeps` | VIEWER, ADMIN | Lists sweeps started after `since` (default = `now - 24h`), ordered by start time descending. |

The `interfaces` endpoint is ADMIN-only because it surfaces NIC names that are otherwise
not exposed to operators — and because the passive sweep that consumes the list is itself
ADMIN-only. A VIEWER request returns `403 Forbidden`.

## Frontend control surfaces

The frontend mounts two panels for the OT/discovery surface:

### `DiscoveryControlPanel`

Lives at `frontend/src/components/DiscoveryControlPanel.tsx`. Drives the passive-discovery
endpoint. On mount it calls `api.listInterfaces()` to populate the interface dropdown; the
list is replaced when the response has at least one entry, otherwise the panel keeps its
hard-coded fallback (`eth0`, `wlan0`). The fallback exists so the panel remains usable
when called by a VIEWER — `api.listInterfaces()` swallows a `403` and returns `[]` so the
panel does not throw, and the controls render disabled with an "ADMIN required" notice. A
VIEWER can therefore see exactly what an ADMIN would be able to trigger, without the
backend ever observing the call.

The source checkboxes track three of the five backend sources (`ARP`, `MDNS`, `PCAP`); LLDP
and CDP are deferred to the managed-switch profile and not surfaced in the panel.

### `OtProbePanel`

Lives at `frontend/src/components/OtProbePanel.tsx`. Wraps `POST /api/ot-probe`. The
protocol dropdown lists Modbus/TCP, DNP3, S7comm, and BACnet/IP; picking a protocol
auto-fills the default port (502 / 20000 / 102 / 47808). The form is gated on `isAdmin`
and renders read-only with disabled inputs and an amber "ADMIN required" badge for
VIEWERs — backend RBAC remains the source of truth regardless. The result panel renders
vendor / product / version / device id / service id / observed-at as a `<dl>`, with a
collapsible `<details>` block exposing the raw protocol fields.

### Client-side 403 graceful degrade

`frontend/src/api/client.ts` exposes `listInterfaces()` with a narrow try/catch — a `403`
response is converted to `[]` rather than thrown so callers can safely render the
fallback list. All other status codes (including transient `5xx` handled by the bounded
retry wrapper) propagate.

```ts
listInterfaces: async (): Promise<InterfaceInfo[]> => {
  try {
    return await request<InterfaceInfo[]>('/api/discovery/interfaces');
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('403')) return [];
    throw err;
  }
},
```

## Concurrency and Timeouts

| Config key | Default | Env var |
|-----------|---------|---------|
| `castellum.ot.probe.connect-timeout-ms` | 3000 | `OT_PROBE_CONNECT_TIMEOUT_MS` |
| `castellum.ot.probe.read-timeout-ms` | 5000 | `OT_PROBE_READ_TIMEOUT_MS` |
| `castellum.ot.probe.total-timeout-ms` | 10000 | `OT_PROBE_TOTAL_TIMEOUT_MS` |
| `castellum.ot.probe.max-concurrent` | 8 | `OT_PROBE_MAX_CONCURRENT` |

`max-concurrent` is enforced by a `java.util.concurrent.Semaphore`. Requests that cannot acquire a
permit within `total-timeout-ms` return HTTP 503.

## Side Effects

A successful probe:

1. Upserts a `device` row (via `DeviceUpsertService`) keyed on `ip_address`.
2. Upserts a `service` row with `vendor`, `product`, and `protocol_family = 'OT_ICS'`.
3. Appends an `audit_log` row with action `OT_PROBE_SUCCESS`.

A failed probe appends an `audit_log` row with action `OT_PROBE_FAILURE` (in a separate
`REQUIRES_NEW` transaction so it survives any enclosing rollback).

## Database Schema Extension (V7)

Migration `V7__service_ot_metadata.sql` extends the `service` table:

```sql
ALTER TABLE service ADD COLUMN vendor          TEXT;
ALTER TABLE service ADD COLUMN product         TEXT;
ALTER TABLE service ADD COLUMN protocol_family TEXT;
CREATE INDEX service_protocol_family_idx ON service (protocol_family)
  WHERE protocol_family IS NOT NULL;  -- Postgres only; H2 mirror omits WHERE
```

## Managed-Switch Lab Profile

The `managed-switch-lab` Maven profile activates two acceptance test classes that exercise LLDP and
CDP probe paths against captured binary fixtures:

| Test class | Decoder under test |
|------------|--------------------|
| `LldpProbeAcceptanceTest` | `io.castellum.discovery.LldpDecoder` |
| `CdpProbeAcceptanceTest`  | `io.castellum.discovery.CdpDecoder`  |

### Activation

```bash
mvn test -Pmanaged-switch-lab
```

This sets the system property `castellum.managed-switch-lab=true`, which the test classes read via
`@EnabledIfSystemProperty(named="castellum.managed-switch-lab", matches="true")`.

Default `mvn test` (no profile) skips both classes silently — no JUnit warning is emitted.

### Fixture-absent skip

Even when the profile is active, each test calls `assumeTrue(fixtureFile.exists(), "managed-switch
fixture missing")` at the top of the method. If the fixture binary has not been committed, the test
aborts silently (abort ≠ failure) with the message `"managed-switch fixture missing"`.

### Adding a fixture

Place captured frames at:

- `backend/src/test/resources/discovery/lldp-sample.bin`
- `backend/src/test/resources/discovery/cdp-sample.bin`

These paths are deferred — capturing real LLDP-MED / CDP frames requires managed-switch
infrastructure. Once committed, the tests automatically progress from *skipped* to *executed* on the
next `mvn test -Pmanaged-switch-lab` run.

### Current stub contract

Until real decoder implementations replace the skeletons, both test methods assert:

```java
assertThatThrownBy(() -> decoder.decode(frameBytes))
    .isInstanceOf(UnsupportedOperationException.class)
    .hasMessageContaining("designed-but-untested");
```

This pins the existing `LldpDecoder` / `CdpDecoder` stub contract and will need updating when the
stubs are replaced with functional implementations.

## Verifying the Read-Only Contract

The automated test `AcceptanceSmokeTest.ac2_surrogateAllProbesEmitOnlyReadFunctionCodes`
asserts byte-by-byte that each probe transmits only read-class function codes against an
in-process surrogate. For high-assurance deployments (NATO IL-3 and above), the contract
must additionally be verified on the wire by an independent operator using a packet
capture tool. This section documents that procedure.

### Procedure

1. **Capture host setup.** On the host that will run the probe (or a SPAN/mirror port that
   sees its egress traffic), start Wireshark or `tshark`:

   ```
   sudo tshark -i <iface> -w /tmp/castellum-ot-probe.pcap \
     'host <target-device-ip> and (tcp port 502 or tcp port 20000 or tcp port 102 or udp port 47808)'
   ```

   Ports above are the well-known Modbus/TCP, DNP3, S7comm, and BACnet/IP defaults. Adjust
   if your device exposes a non-default port.

2. **Issue the probe.** From the operator console:

   ```
   curl -X POST http://<castellum-host>:8080/api/ot-probe \
        -H 'Content-Type: application/json' \
        -d '{"deviceId": <id>, "protocol": "MODBUS_TCP"}'
   ```

   Repeat once per protocol you need to certify.

3. **Stop the capture** (`Ctrl-C`) and open the `.pcap` in Wireshark.

### What to Confirm Per Protocol

For every captured packet whose TCP/UDP payload originates from Castellum, decode the
application layer and confirm the function code matches the whitelist below. Any code
outside this set is a contract violation and must be reported as a security incident.

| Protocol | Allowed function codes | Wireshark display filter |
|----------|------------------------|--------------------------|
| Modbus/TCP | `0x01` Read Coils, `0x02` Read Discrete Inputs, `0x03` Read Holding Registers, `0x04` Read Input Registers, `0x2B` MEI Read Device Identification (sub-code `0x0E`) | `mbtcp.func_code in {1 2 3 4 43}` |
| DNP3 | `0x01` Read (groups 60 var 1-4 class data, group 0 var 254 device attribute) | `dnp3.al.func == 1` |
| S7comm | `0xF0` Setup Communication, `0x00` Read SZL (function group `0x04`, sub-function `0x01`, SZL-IDs `0x0011`/`0x001C`) | `s7comm.param.func in {0xF0 0x00}` |
| BACnet/IP | `0x0C` ReadProperty, `0x0E` ReadPropertyMultiple, `0x08` Who-Is | `bacapp.confirmed_service in {12 14}` or `bacapp.unconfirmed_service == 8` |

### Forbidden Codes — Alert If Seen

If any of the following appear in a Castellum-originated frame, the read-only contract is
breached and the build must be treated as compromised:

| Protocol | Forbidden codes (non-exhaustive) |
|----------|----------------------------------|
| Modbus/TCP | `0x05` Write Single Coil, `0x06` Write Single Register, `0x0F` Write Multiple Coils, `0x10` Write Multiple Registers, `0x16` Mask Write Register |
| DNP3 | `0x02` Write, `0x03`/`0x04` Select/Operate, `0x05` Direct Operate, `0x06` Direct Operate No-Ack, `0x0D` Cold Restart, `0x0E` Warm Restart |
| S7comm | Function group `0x05` Write Var, any PLC-Stop / PLC-Start / Force / Block-Download |
| BACnet/IP | `0x0F` WriteProperty, `0x10` WritePropertyMultiple, `0x14` ReinitializeDevice, `0x11` DeviceCommunicationControl |

### Pass Criteria

The capture passes the read-only contract when:

1. Every Castellum-originated application-layer frame is decoded by Wireshark without
   "malformed packet" warnings.
2. Every observed function code appears in the **Allowed** table for its protocol.
3. No code from the **Forbidden** table appears in any frame.
4. The capture covers at least one full request/response cycle per protocol under test.

Archive the `.pcap` and a screenshot of the Wireshark protocol hierarchy alongside the
acceptance test log as evidence for the certification package.

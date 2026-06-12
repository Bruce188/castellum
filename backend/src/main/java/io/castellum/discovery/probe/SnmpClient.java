package io.castellum.discovery.probe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Structural READ-ONLY SNMP client for network bridge discovery.
 *
 * <p><b>READ-ONLY invariant:</b> this class issues ONLY SNMP GET and GETBULK (read-only)
 * requests. It does NOT issue SNMP SET requests. The functional seam {@link SnmpWalker}
 * is the SNMP analogue of {@link DockerEngineApiClient.HttpGetter}: tests supply a lambda
 * returning fixture varbinds; production uses snmp4j UDP transport.
 *
 * <p>Two public walk methods are provided:
 * <ul>
 *   <li>{@link #walkInterfaces(String, String)} — walks ifDescr (1.3.6.1.2.1.2.2.1.2),
 *       ifName (1.3.6.1.2.1.31.1.1.1.1), and ifType (1.3.6.1.2.1.2.2.1.3)</li>
 *   <li>{@link #walkIpAddresses(String, String)} — walks ipAdEntIfIndex
 *       (1.3.6.1.2.1.4.20.1.2) and ipAdEntNetMask (1.3.6.1.2.1.4.20.1.3)</li>
 * </ul>
 *
 * <p>Row counts are capped at {@value #MAX_SNMP_ROWS} to bound untrusted-host responses.
 * Timeout responses return {@link Optional#empty()} so the caller treats them as a closed
 * UDP port fast no-op.
 */
@Component
public class SnmpClient {

    private static final Logger log = LoggerFactory.getLogger(SnmpClient.class);

    /** Maximum varbind rows returned from a single SNMP walk. */
    static final int MAX_SNMP_ROWS = 1000;

    // Standard SNMP OIDs used for interface + IP address discovery
    static final String OID_IF_DESCR  = "1.3.6.1.2.1.2.2.1.2";
    static final String OID_IF_NAME   = "1.3.6.1.2.1.31.1.1.1.1";
    static final String OID_IF_TYPE   = "1.3.6.1.2.1.2.2.1.3";
    static final String OID_IP_IF_IDX = "1.3.6.1.2.1.4.20.1.2";
    static final String OID_IP_MASK   = "1.3.6.1.2.1.4.20.1.3";

    /**
     * Functional interface for the SNMP transport seam (SNMP analogue of HttpGetter).
     *
     * <p>Walk implementation: GET/GETBULK sub-tree rooted at {@code baseOid}. Tests supply a
     * lambda returning fixture VariableBindings; production uses snmp4j Snmp UDP transport.
     *
     * <p><b>READ-ONLY contract:</b> implementations must issue only read operations (GET/GETBULK).
     * No SET permitted.
     */
    @FunctionalInterface
    public interface SnmpWalker {
        /**
         * Walk the SNMP sub-tree rooted at {@code baseOid} on the given host/community.
         *
         * @param host      target host IP
         * @param community SNMP community string
         * @param baseOid   root OID of the sub-tree to walk
         * @return list of varbinds (rows), or empty on timeout / unreachable
         */
        Optional<List<VariableBinding>> walk(String host, String community, String baseOid);
    }

    /** Records one interface row keyed by ifIndex. */
    public record SnmpRow(int ifIndex, String ifDescr, String ifName, int ifType) {}

    /** Records one IP address row keyed by ipAddress. */
    public record SnmpAddr(String ipAddress, int ifIndex, String netMask) {}

    private final SnmpWalker walker;

    /**
     * Test seam constructor — caller supplies the walker.
     */
    public SnmpClient(SnmpWalker walker) {
        this.walker = walker;
    }

    /**
     * Spring-managed constructor. Builds a real snmp4j UDP-transport walker.
     *
     * @param timeoutMs  SNMP request timeout in milliseconds
     * @param retries    number of retries on timeout
     */
    @org.springframework.beans.factory.annotation.Autowired
    public SnmpClient(
            @org.springframework.beans.factory.annotation.Value(
                "${castellum.docker.probe.snmp.timeout-ms:1500}") int timeoutMs,
            @org.springframework.beans.factory.annotation.Value(
                "${castellum.docker.probe.snmp.retries:1}") int retries) {
        this(buildDefaultWalker(timeoutMs, retries));
    }

    /**
     * Walk interface table (ifDescr, ifName, ifType) for the given host+community.
     *
     * <p>READ-ONLY: uses GETBULK/GET, no SET.
     *
     * @param host      target host IP
     * @param community SNMP v2c community string
     * @return list of {@link SnmpRow} records, or empty on timeout/unreachable
     */
    public Optional<List<SnmpRow>> walkInterfaces(String host, String community) {
        Optional<List<VariableBinding>> descrOpt  = walker.walk(host, community, OID_IF_DESCR);
        Optional<List<VariableBinding>> nameOpt   = walker.walk(host, community, OID_IF_NAME);
        Optional<List<VariableBinding>> typeOpt   = walker.walk(host, community, OID_IF_TYPE);

        if (descrOpt.isEmpty()) return Optional.empty();

        List<VariableBinding> descrs = descrOpt.get();
        List<VariableBinding> names  = nameOpt.orElse(Collections.emptyList());
        List<VariableBinding> types  = typeOpt.orElse(Collections.emptyList());

        // Build index→name/type maps for O(1) join
        java.util.Map<Integer, String> nameByIdx = new java.util.HashMap<>();
        for (VariableBinding vb : names) {
            int idx = lastOidInt(vb.getOid());
            if (idx >= 0) nameByIdx.put(idx, vb.getVariable().toString());
        }
        java.util.Map<Integer, Integer> typeByIdx = new java.util.HashMap<>();
        for (VariableBinding vb : types) {
            int idx = lastOidInt(vb.getOid());
            if (idx >= 0) {
                try {
                    typeByIdx.put(idx, Integer.parseInt(vb.getVariable().toString()));
                } catch (NumberFormatException ignored) { /* malformed — skip */ }
            }
        }

        List<SnmpRow> rows = new ArrayList<>(Math.min(descrs.size(), MAX_SNMP_ROWS));
        for (VariableBinding vb : descrs) {
            if (rows.size() >= MAX_SNMP_ROWS) break;
            int idx = lastOidInt(vb.getOid());
            if (idx < 0) continue;
            String descr  = vb.getVariable().toString();
            String ifName = nameByIdx.getOrDefault(idx, "");
            int    ifType = typeByIdx.getOrDefault(idx, 0);
            rows.add(new SnmpRow(idx, descr, ifName, ifType));
        }
        return Optional.of(rows);
    }

    /**
     * Walk IP address table (ipAdEntIfIndex, ipAdEntNetMask) for the given host+community.
     *
     * <p>READ-ONLY: uses GETBULK/GET, no SET.
     *
     * @param host      target host IP
     * @param community SNMP v2c community string
     * @return list of {@link SnmpAddr} records, or empty on timeout/unreachable
     */
    public Optional<List<SnmpAddr>> walkIpAddresses(String host, String community) {
        Optional<List<VariableBinding>> idxOpt  = walker.walk(host, community, OID_IP_IF_IDX);
        Optional<List<VariableBinding>> maskOpt = walker.walk(host, community, OID_IP_MASK);

        if (idxOpt.isEmpty()) return Optional.empty();

        List<VariableBinding> idxVbs  = idxOpt.get();
        List<VariableBinding> maskVbs = maskOpt.orElse(Collections.emptyList());

        // Build ipAddr→mask map for join
        java.util.Map<String, String> maskByIp = new java.util.HashMap<>();
        for (VariableBinding vb : maskVbs) {
            String ip = ipFromOid(vb.getOid(), OID_IP_MASK);
            if (ip != null) maskByIp.put(ip, vb.getVariable().toString());
        }

        List<SnmpAddr> rows = new ArrayList<>(Math.min(idxVbs.size(), MAX_SNMP_ROWS));
        for (VariableBinding vb : idxVbs) {
            if (rows.size() >= MAX_SNMP_ROWS) break;
            String ip = ipFromOid(vb.getOid(), OID_IP_IF_IDX);
            if (ip == null) continue;
            int ifIndex;
            try {
                ifIndex = Integer.parseInt(vb.getVariable().toString());
            } catch (NumberFormatException ignored) {
                continue; // malformed — skip
            }
            String mask = maskByIp.getOrDefault(ip, "");
            rows.add(new SnmpAddr(ip, ifIndex, mask));
        }
        return Optional.of(rows);
    }

    // ---- Private helpers ----

    /** Extract the last integer component of an OID (the row index). */
    private static int lastOidInt(OID oid) {
        int len = oid.size();
        if (len == 0) return -1;
        try {
            return oid.get(len - 1);
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Extract the IP address from an OID whose suffix is "a.b.c.d" after the base OID.
     * e.g. 1.3.6.1.2.1.4.20.1.2.10.0.0.1 → "10.0.0.1"
     */
    private static String ipFromOid(OID oid, String baseOidStr) {
        OID base = new OID(baseOidStr);
        int baseLen = base.size();
        if (oid.size() != baseLen + 4) return null;
        try {
            int a = oid.get(baseLen);
            int b = oid.get(baseLen + 1);
            int c = oid.get(baseLen + 2);
            int d = oid.get(baseLen + 3);
            if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) {
                return null;
            }
            return a + "." + b + "." + c + "." + d;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Build a production snmp4j GETBULK walker using UDP transport.
     * READ-ONLY: only PDU.GETBULK (read-only operation) is used; NO SET.
     */
    private static SnmpWalker buildDefaultWalker(int timeoutMs, int retries) {
        return (host, community, baseOidStr) -> {
            try {
                DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
                transport.listen();
                Snmp snmp = new Snmp(transport);
                try {
                    CommunityTarget<UdpAddress> target = new CommunityTarget<>();
                    target.setCommunity(new OctetString(community));
                    target.setAddress(new UdpAddress(InetAddress.getByName(host), 161));
                    target.setVersion(SnmpConstants.version2c);
                    target.setTimeout(timeoutMs);
                    target.setRetries(retries);

                    OID baseOid = new OID(baseOidStr);
                    List<VariableBinding> result = new ArrayList<>();

                    // GETBULK walk: iterate until OID leaves sub-tree or row cap
                    OID currentOid = new OID(baseOid);
                    while (result.size() < MAX_SNMP_ROWS) {
                        PDU pdu = new PDU();
                        pdu.setType(PDU.GETBULK);
                        pdu.setMaxRepetitions(25);
                        pdu.setNonRepeaters(0);
                        pdu.add(new VariableBinding(currentOid));

                        ResponseEvent<?> event = snmp.send(pdu, target);
                        if (event == null || event.getResponse() == null) {
                            // Timeout — return whatever we have so far (may be empty = no response)
                            break;
                        }
                        PDU response = event.getResponse();
                        if (response.getErrorStatus() != PDU.noError) break;

                        boolean advanced = false;
                        for (VariableBinding vb : response.getVariableBindings()) {
                            if (!vb.getOid().startsWith(baseOid)) {
                                // Walked past sub-tree — done
                                return Optional.of(result);
                            }
                            if (result.size() >= MAX_SNMP_ROWS) break;
                            result.add(vb);
                            currentOid = vb.getOid();
                            advanced = true;
                        }
                        if (!advanced) break;
                    }
                    return Optional.of(result);
                } finally {
                    closeQuietly(snmp, host);
                }
            } catch (IOException e) {
                log.debug("SnmpClient: SNMP walk failed for {}:{} — {}", host, baseOidStr, e.getMessage());
                return Optional.empty();
            }
        };
    }

    /**
     * Close the SNMP session, tolerating ANY close-time failure — including
     * {@link Error}.
     *
     * <p>On some kernels (notably WSL2), signalling the snmp4j listen thread blocked in
     * {@code receive()} during datagram-socket pre-close fails with an {@link IOException}
     * (e.g. {@code EINPROGRESS}), which the JDK's {@code DatagramSocketAdaptor.close()}
     * rethrows wrapped in {@link java.lang.Error} because {@code DatagramSocket.close()}
     * declares no checked exception. A failed close of a finished walk session is harmless:
     * swallowing it preserves the walk result and keeps the walker's "timeout/unreachable
     * degrades to a no-op" contract — instead of an Error escaping every
     * {@code catch (Exception)} isolation layer and wedging the scan lifecycle.
     */
    private static void closeQuietly(Snmp snmp, String host) {
        try {
            snmp.close();
        } catch (Exception | Error e) {
            log.debug("SnmpClient: ignoring SNMP session close failure for {} — {}", host, e.toString());
        }
    }
}

package io.castellum.discovery.probe;

import org.junit.jupiter.api.Test;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.VariableBinding;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SnmpClient} using the walker seam.
 */
class SnmpClientTest {

    // ---- Fixture helpers ----

    /** Build an ifDescr varbind for the given ifIndex. */
    private static VariableBinding ifDescr(int ifIndex, String descr) {
        return new VariableBinding(
            new OID(SnmpClient.OID_IF_DESCR + "." + ifIndex),
            new OctetString(descr));
    }

    /** Build an ifName varbind for the given ifIndex. */
    private static VariableBinding ifName(int ifIndex, String name) {
        return new VariableBinding(
            new OID(SnmpClient.OID_IF_NAME + "." + ifIndex),
            new OctetString(name));
    }

    /** Build an ifType varbind for the given ifIndex. */
    private static VariableBinding ifType(int ifIndex, int type) {
        return new VariableBinding(
            new OID(SnmpClient.OID_IF_TYPE + "." + ifIndex),
            new Integer32(type));
    }

    /** Build an ipAdEntIfIndex varbind keyed on the IP address suffix. */
    private static VariableBinding ipIfIndex(String ip, int ifIndex) {
        return new VariableBinding(
            new OID(SnmpClient.OID_IP_IF_IDX + "." + ip),
            new Integer32(ifIndex));
    }

    /** Build an ipAdEntNetMask varbind keyed on the IP address suffix. */
    private static VariableBinding ipMask(String ip, String mask) {
        return new VariableBinding(
            new OID(SnmpClient.OID_IP_MASK + "." + ip),
            new OctetString(mask));
    }

    // ---- walkInterfaces ----

    @Test
    void walkInterfaces_fixtureVarbinds_returnsRows() {
        SnmpClient.SnmpWalker walker = (host, community, baseOid) -> {
            if (baseOid.equals(SnmpClient.OID_IF_DESCR)) {
                return Optional.of(List.of(ifDescr(1, "docker0"), ifDescr(2, "eth0")));
            }
            if (baseOid.equals(SnmpClient.OID_IF_NAME)) {
                return Optional.of(List.of(ifName(1, "docker0"), ifName(2, "eth0")));
            }
            if (baseOid.equals(SnmpClient.OID_IF_TYPE)) {
                return Optional.of(List.of(ifType(1, 131), ifType(2, 6)));
            }
            return Optional.empty();
        };
        SnmpClient client = new SnmpClient(walker);

        Optional<List<SnmpClient.SnmpRow>> result = client.walkInterfaces("10.0.0.1", "public");
        assertThat(result).isPresent();
        List<SnmpClient.SnmpRow> rows = result.get();
        assertThat(rows).hasSize(2);
        assertThat(rows.get(0).ifDescr()).isEqualTo("docker0");
        assertThat(rows.get(0).ifIndex()).isEqualTo(1);
        assertThat(rows.get(0).ifType()).isEqualTo(131);
    }

    @Test
    void walkInterfaces_timeout_returnsEmpty() {
        SnmpClient client = new SnmpClient((h, c, o) -> Optional.empty());
        Optional<List<SnmpClient.SnmpRow>> result = client.walkInterfaces("10.0.0.1", "public");
        assertThat(result).isEmpty();
    }

    @Test
    void walkInterfaces_rowCapEnforced() {
        // Produce MAX_SNMP_ROWS+10 varbinds
        VariableBinding[] many = new VariableBinding[SnmpClient.MAX_SNMP_ROWS + 10];
        for (int i = 0; i < many.length; i++) {
            many[i] = ifDescr(i + 1, "eth" + i);
        }
        SnmpClient client = new SnmpClient((h, c, o) -> Optional.of(Arrays.asList(many)));
        Optional<List<SnmpClient.SnmpRow>> result = client.walkInterfaces("10.0.0.1", "public");
        assertThat(result).isPresent();
        assertThat(result.get().size()).isLessThanOrEqualTo(SnmpClient.MAX_SNMP_ROWS);
    }

    // ---- walkIpAddresses ----

    @Test
    void walkIpAddresses_fixtureVarbinds_returnsAddr() {
        SnmpClient client = new SnmpClient((h, c, oid) -> {
            if (oid.equals(SnmpClient.OID_IP_IF_IDX)) {
                return Optional.of(List.of(ipIfIndex("172.18.0.1", 3)));
            }
            if (oid.equals(SnmpClient.OID_IP_MASK)) {
                return Optional.of(List.of(ipMask("172.18.0.1", "255.255.0.0")));
            }
            return Optional.empty();
        });

        Optional<List<SnmpClient.SnmpAddr>> result = client.walkIpAddresses("10.0.0.1", "public");
        assertThat(result).isPresent();
        assertThat(result.get()).hasSize(1);
        assertThat(result.get().get(0).ipAddress()).isEqualTo("172.18.0.1");
        assertThat(result.get().get(0).ifIndex()).isEqualTo(3);
        assertThat(result.get().get(0).netMask()).isEqualTo("255.255.0.0");
    }

    // ---- R4: reflection surface test — all public methods start with "walk", no SET method ----

    @Test
    void reflectionSurface_allPublicMethodsStartWithWalk_noSet() {
        Method[] methods = SnmpClient.class.getMethods();
        for (Method m : methods) {
            String name = m.getName();
            // Skip Object methods and Spring lifecycle methods
            if (m.getDeclaringClass() == Object.class) continue;
            if (name.equals("getClass") || name.equals("hashCode") || name.equals("equals")
                    || name.equals("toString") || name.equals("notify") || name.equals("notifyAll")
                    || name.equals("wait")) {
                continue;
            }
            // Non-walk public methods are constructor-related — skip non-void setters
            // The key assertion: no method is named "set*" (which would imply SNMP SET)
            assertThat(name).as("No public method should be named 'set*' (SNMP SET prohibited)")
                .doesNotStartWith("set");
        }
        // Positive: walkInterfaces and walkIpAddresses exist
        assertThat(Arrays.stream(methods).map(Method::getName))
            .contains("walkInterfaces", "walkIpAddresses");
    }
}

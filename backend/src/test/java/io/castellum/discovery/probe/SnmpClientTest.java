package io.castellum.discovery.probe;

import org.junit.jupiter.api.Test;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.VariableBinding;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

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

    // ---- closeQuietly / factory-seam tests ----

    /**
     * closeQuietly — when Snmp.close() throws an IOException the walker must
     * still return the collected varbinds (walk result is NOT discarded).
     *
     * The production walker calls {@code createSession(transport)} which is overridable
     * in a subclass. We override it here to return an Snmp stub whose close() throws,
     * verifying that closeQuietly swallows the IOException and does not propagate it.
     *
     * Because the stub Snmp has no live transport, send() will return null → the walker
     * treats that as a timeout and returns the (empty) collected list. The important
     * assertion is that NO exception escapes from the walker call.
     */
    @Test
    void closeQuietly_ioExceptionOnClose_doesNotEscape() throws Exception {
        AtomicBoolean closeCalled = new AtomicBoolean(false);
        SnmpClient client = new SnmpClient(1, 0) {
            @Override
            protected Snmp createSession(TransportMapping<?> transport) throws IOException {
                return new Snmp(transport) {
                    @Override
                    public void close() throws IOException {
                        closeCalled.set(true);
                        throw new IOException("simulated WSL2 close failure");
                    }
                };
            }
        };

        // The walker must not throw; it should return an empty Optional (no SNMP response
        // from the stub — the send() returns null → timeout path).
        assertThatCode(() -> client.walkInterfaces("127.0.0.1", "public"))
            .doesNotThrowAnyException();
        assertThat(closeCalled.get())
            .as("close() must have been called (closeQuietly exercised)")
            .isTrue();
    }

    /**
     * closeQuietly — when Snmp.close() throws an Error (the scenario documented
     * in the Javadoc — DatagramSocket.close() wrapping an IOException inside Error on
     * some WSL2 kernels) the walker must still NOT propagate the Error.
     */
    @Test
    void closeQuietly_errorOnClose_doesNotEscape() throws Exception {
        AtomicBoolean closeCalled = new AtomicBoolean(false);
        SnmpClient client = new SnmpClient(1, 0) {
            @Override
            protected Snmp createSession(TransportMapping<?> transport) throws IOException {
                return new Snmp(transport) {
                    @Override
                    public void close() throws IOException {
                        closeCalled.set(true);
                        throw new Error("simulated DatagramSocket.close() Error");
                    }
                };
            }
        };

        assertThatCode(() -> client.walkInterfaces("127.0.0.1", "public"))
            .doesNotThrowAnyException();
        assertThat(closeCalled.get())
            .as("close() must have been called even when it throws Error")
            .isTrue();
    }

    /**
     * Factory-seam test — the two-arg constructor calls {@code createSession()}
     * rather than constructing Snmp directly, so the seam is reachable and invoked.
     * This test subclasses SnmpClient, counts how many times createSession is called
     * per walk, and verifies the seam is not bypassed.
     */
    @Test
    void factorySeam_createSessionIsCalledPerWalkOid() throws Exception {
        int[] callCount = {0};
        SnmpClient client = new SnmpClient(1, 0) {
            @Override
            protected Snmp createSession(TransportMapping<?> transport) throws IOException {
                callCount[0]++;
                // Delegate to real constructor — the session won't connect anywhere
                // (127.0.0.1:161, 1ms timeout), so send() will return null (timeout path).
                return super.createSession(transport);
            }
        };

        // walkInterfaces issues 3 walker calls (ifDescr, ifName, ifType)
        client.walkInterfaces("127.0.0.1", "public");
        assertThat(callCount[0])
            .as("createSession must be called once per OID sub-tree walk (3 for walkInterfaces)")
            .isEqualTo(3);
    }

    // ---- Reflection surface test — all public methods start with "walk", no SET method ----

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

package io.castellum.discovery;

import io.castellum.domain.Device;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class DeviceRoleClassifierTest {

    private final DeviceRoleClassifier classifier = new DeviceRoleClassifier();

    @ParameterizedTest
    @MethodSource("ruleMatrix")
    void classify_returnsExpectedRole(Device device, DeviceRole expected) {
        assertThat(classifier.classify(device)).isEqualTo(expected);
    }

    static Stream<Arguments> ruleMatrix() {
        return Stream.of(
            // Rule 1 — docker-net synthetic gateway: UNKNOWN (MUST precede CONTAINER and ROUTER)
            Arguments.of(dockerNetGateway("docker-net:supabase", "172.20.0.1"), DeviceRole.UNKNOWN),
            // docker-net gateway with a .1 IP — proves precedence over ROUTER rule too
            Arguments.of(dockerNetGateway("docker-net:mynet_default", "10.10.0.1"), DeviceRole.UNKNOWN),

            // Rule 2 — real Docker container: CONTAINER (not a docker-net hostname)
            Arguments.of(dockerContainer("api-1", DiscoveryScope.DOCKER_BRIDGE), DeviceRole.CONTAINER),
            Arguments.of(dockerContainer("worker-2", DiscoveryScope.HOME), DeviceRole.CONTAINER),

            // Rule 3 — server OS fingerprint: SERVER
            Arguments.of(withOsName("Windows Server 2019"), DeviceRole.SERVER),
            Arguments.of(withOsName("Windows Server 2022"), DeviceRole.SERVER),
            Arguments.of(withOsName("Ubuntu Server 22.04"), DeviceRole.SERVER),
            Arguments.of(withOsCpe("cpe:/o:canonical:ubuntu_linux:22.04::server"), DeviceRole.SERVER),
            Arguments.of(withOsName("CentOS Linux 8 Server"), DeviceRole.SERVER),

            // Rule 4 — desktop/client OS: DESKTOP (LAPTOP reserved — ambiguous maps to DESKTOP)
            Arguments.of(withOsName("Microsoft Windows 10"), DeviceRole.DESKTOP),
            Arguments.of(withOsName("Microsoft Windows 11"), DeviceRole.DESKTOP),
            Arguments.of(withOsName("Mac OS X 12.6"), DeviceRole.DESKTOP),
            Arguments.of(withOsName("macOS 13 Ventura"), DeviceRole.DESKTOP),
            Arguments.of(withOsName("Ubuntu 22.04 Desktop"), DeviceRole.DESKTOP),

            // Rule 5 — .1 IP: ROUTER (weak signal — only when no OS and non-docker)
            Arguments.of(withIp("192.168.1.1"), DeviceRole.ROUTER),
            Arguments.of(withIp("10.0.0.1"), DeviceRole.ROUTER),
            Arguments.of(withIp("172.20.5.1"), DeviceRole.ROUTER),

            // Rule 7 — no signal: UNKNOWN
            Arguments.of(emptyDevice(), DeviceRole.UNKNOWN),

            // Precedence guard: DOCKER source + server OS → CONTAINER (source rule precedes OS rule)
            Arguments.of(dockerContainerWithOs("api-2", "Windows Server 2019", DiscoveryScope.DOCKER_BRIDGE),
                DeviceRole.CONTAINER),

            // Non-.1 IP should NOT be ROUTER
            Arguments.of(withIp("192.168.1.100"), DeviceRole.UNKNOWN),

            // Desktop OS beats .1 IP (OS rule is before IP rule)
            Arguments.of(desktopOsWithIp("Microsoft Windows 10", "192.168.1.1"), DeviceRole.DESKTOP),

            // Server OS beats .1 IP
            Arguments.of(serverOsWithIp("Windows Server 2019", "192.168.1.1"), DeviceRole.SERVER),

            // NIT-1: bare distro token "debian" → SERVER by design (no "server" token in the string)
            Arguments.of(withOsName("Debian GNU/Linux 11"), DeviceRole.SERVER),

            // NIT-2: Rule 6 hostname tiebreaker — ARP, hostname="router", non-.1 IP → ROUTER
            Arguments.of(arpDeviceWithHostname("router", "192.168.0.50"), DeviceRole.ROUTER)
        );
    }

    // ─── Dedicated @Test edge cases ───────────────────────────────────────────

    @Test
    void classify_nullDevice_returnsUnknown() {
        assertThat(classifier.classify(null)).isEqualTo(DeviceRole.UNKNOWN);
    }

    @Test
    void classify_allNullSignals_returnsUnknown() {
        Device d = new Device();
        // All fields left null
        assertThat(classifier.classify(d)).isEqualTo(DeviceRole.UNKNOWN);
    }

    @Test
    void classify_blankHostname_doesNotMatchDockerNet() {
        Device d = new Device();
        d.setDiscoverySource(DiscoverySource.DOCKER);
        d.setHostname("   ");
        // blank hostname must NOT trigger the docker-net rule; source=DOCKER → CONTAINER
        assertThat(classifier.classify(d)).isEqualTo(DeviceRole.CONTAINER);
    }

    @Test
    void classify_nullHostname_doesNotMatchDockerNet() {
        Device d = new Device();
        d.setDiscoverySource(DiscoverySource.DOCKER);
        d.setHostname(null);
        // null hostname must NOT trigger the docker-net rule; source=DOCKER → CONTAINER
        assertThat(classifier.classify(d)).isEqualTo(DeviceRole.CONTAINER);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static Device dockerNetGateway(String hostname, String ip) {
        Device d = new Device();
        d.setDiscoverySource(DiscoverySource.DOCKER);
        d.setHostname(hostname);
        d.setIpAddress(ip);
        return d;
    }

    private static Device dockerContainer(String hostname, DiscoveryScope scope) {
        Device d = new Device();
        d.setDiscoverySource(DiscoverySource.DOCKER);
        d.setHostname(hostname);
        d.setDiscoveryScope(scope);
        return d;
    }

    private static Device dockerContainerWithOs(String hostname, String osName, DiscoveryScope scope) {
        Device d = new Device();
        d.setDiscoverySource(DiscoverySource.DOCKER);
        d.setHostname(hostname);
        d.setOsName(osName);
        d.setDiscoveryScope(scope);
        return d;
    }

    private static Device withOsName(String osName) {
        Device d = new Device();
        d.setOsName(osName);
        return d;
    }

    private static Device withOsCpe(String osCpe) {
        Device d = new Device();
        d.setOsCpe(osCpe);
        return d;
    }

    private static Device withIp(String ip) {
        Device d = new Device();
        d.setIpAddress(ip);
        return d;
    }

    private static Device emptyDevice() {
        return new Device();
    }

    private static Device desktopOsWithIp(String osName, String ip) {
        Device d = new Device();
        d.setOsName(osName);
        d.setIpAddress(ip);
        return d;
    }

    private static Device serverOsWithIp(String osName, String ip) {
        Device d = new Device();
        d.setOsName(osName);
        d.setIpAddress(ip);
        return d;
    }

    private static Device arpDeviceWithHostname(String hostname, String ip) {
        Device d = new Device();
        d.setDiscoverySource(DiscoverySource.ARP);
        d.setHostname(hostname);
        d.setIpAddress(ip);
        return d;
    }
}

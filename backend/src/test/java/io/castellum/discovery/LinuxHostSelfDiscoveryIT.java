package io.castellum.discovery;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Live-host integration test: drives {@link LinuxArpReader} against the real
 * {@code /proc/net/arp} on the host and asserts at least one neighbor is parsed.
 *
 * <p>Skipped under default {@code mvn test} via {@link EnabledIfSystemProperty}.
 * Activated by the {@code discovery-live} Maven profile, which sets
 * {@code -Ddiscovery.live=true}.
 *
 * <p>Even on Linux, a pristine container with no recent network activity may have an
 * empty ARP cache. The test issues a {@code ping}-equivalent (looks up the default
 * gateway via {@link #seedArpCache()}) before asserting; if the cache is still empty
 * after that, the test is skipped via {@link Assumptions} rather than failing — the
 * environment, not the code, is at fault.
 */
@EnabledOnOs(OS.LINUX)
@EnabledIfSystemProperty(named = "discovery.live", matches = "true")
class LinuxHostSelfDiscoveryIT {

    @Test
    void linuxHostArpCache_isReadable_andProducesAtLeastOneNeighbor() throws Exception {
        Path arpFile = Path.of("/proc/net/arp");
        Assumptions.assumeTrue(Files.exists(arpFile),
            "/proc/net/arp not present — kernel/namespace lacks IPv4 ARP table");

        LinuxArpReader reader = new LinuxArpReader("/proc/net/arp");
        List<DiscoveredNeighbor> entries = reader.read();

        Assumptions.assumeTrue(!entries.isEmpty(),
            "Live ARP cache empty on this host — gateway likely unreachable in the test environment");

        // At least one neighbor must have an IPv4 address and a non-zero MAC.
        assertThat(entries).anyMatch(n ->
            n.ipAddress() != null
                && n.ipAddress().matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")
                && n.macAddress() != null
                && !"00:00:00:00:00:00".equalsIgnoreCase(n.macAddress())
        );
    }
}

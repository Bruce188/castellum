package io.castellum.discovery;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ArpCacheReaderSelfDiscoveryTest {

    @Test
    void ac1_passiveDiscoveryFindsSelfViaArp() throws Exception {
        // Find a non-loopback IPv4 address. If none, skip via assumption.
        String localIp = findNonLoopbackIpv4();
        Assumptions.assumeTrue(localIp != null, "no non-loopback IPv4 interface available");

        Path arpFixture = Files.createTempFile("proc-net-arp", ".txt");
        String content = String.join("\n",
            "IP address       HW type     Flags       HW address            Mask     Device",
            localIp + "      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0",
            ""
        );
        Files.writeString(arpFixture, content, StandardCharsets.UTF_8);

        ArpCacheReader reader = new ArpCacheReader(arpFixture.toString());
        List<DiscoveredNeighbor> entries = reader.read();

        assertThat(entries).isNotEmpty();
        assertThat(entries).anyMatch(e -> e.ipAddress().equals(localIp));
    }

    private static String findNonLoopbackIpv4() throws Exception {
        Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
        while (nets.hasMoreElements()) {
            NetworkInterface ni = nets.nextElement();
            if (ni.isLoopback() || !ni.isUp()) continue;
            Enumeration<InetAddress> addrs = ni.getInetAddresses();
            while (addrs.hasMoreElements()) {
                InetAddress addr = addrs.nextElement();
                if (addr.getHostAddress().matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")
                    && !addr.isLoopbackAddress()
                    && !addr.isLinkLocalAddress()) {
                    return addr.getHostAddress();
                }
            }
        }
        return null;
    }
}

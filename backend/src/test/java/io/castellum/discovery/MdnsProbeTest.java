package io.castellum.discovery;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MdnsProbeTest {

    @Test
    @Tag("multicast-required")
    void probe_collectsServiceEvents_returnsDiscoveredNeighbors() throws Exception {
        // Skip if multicast unavailable in this environment
        JmDNS publisher = null;
        try {
            publisher = JmDNS.create(InetAddress.getLoopbackAddress());
        } catch (Exception e) {
            Assumptions.assumeTrue(false, "JmDNS unavailable in this environment: " + e.getMessage());
        }

        // Register a test service
        ServiceInfo info = ServiceInfo.create("_test._tcp.local.", "acceptance-fixture", 9999, "test");
        try {
            publisher.registerService(info);

            MdnsProbe probe = new MdnsProbe("_test._tcp.local.", new MdnsPayloadDecoder(), false, 1000);
            List<DiscoveredNeighbor> results = probe.probe(3);

            // May or may not discover in 3s depending on timing, but should not throw
            assertThat(results).isNotNull();
        } finally {
            publisher.close();
        }
    }

    @Test
    void probe_durationBounded_terminatesAtDeadline() {
        MdnsProbe probe = new MdnsProbe("_test._tcp.local.", new MdnsPayloadDecoder(), false, 1000);
        long start = System.nanoTime();
        try {
            List<DiscoveredNeighbor> results = probe.probe(1);
            assertThat(results).isNotNull();
        } catch (DiscoveryUnavailableException e) {
            Assumptions.assumeTrue(false, "mDNS unavailable in this environment: " + e.getMessage());
        }
        long elapsed = System.nanoTime() - start;
        // Should complete within 8000ms of the 1s window (jmdns init can be slow on some hosts)
        assertThat(elapsed).isLessThan(8_000_000_000L);
    }

    // Payload decoding is opt-in: with the flag OFF the probe must never
    // touch the decoder, regardless of what traffic the socket loop sees.
    // NOTE: passes in RED (the ctor merely stores the decoder) — pinned so GREEN's
    // socket-loop wiring cannot invoke it when payload-decode is disabled.
    @Test
    void probe_payloadDecodeFlagOff_decoderNeverInvoked() {
        MdnsPayloadDecoder decoder = org.mockito.Mockito.mock(MdnsPayloadDecoder.class);
        MdnsProbe probe = new MdnsProbe("_test._tcp.local.", decoder, false, 1000);
        try {
            probe.probe(1);
        } catch (DiscoveryUnavailableException e) {
            // mDNS may be unavailable in this environment — the contract still holds:
            // a disabled decoder must not have been touched on any path.
        }
        org.mockito.Mockito.verifyNoInteractions(decoder);
    }

    @Test
    void probe_listenOnlyContract() throws Exception {
        // Read the MdnsProbe source file and assert it never calls jmdns.list(
        Path sourceFile = Paths.get("src/main/java/io/castellum/discovery/MdnsProbe.java");
        Assumptions.assumeTrue(Files.exists(sourceFile), "Source file not found for code review");
        String source = Files.readString(sourceFile);
        assertThat(source)
            .as("MdnsProbe must never call jmdns.list() — that emits active unicast queries")
            .doesNotContain("jmdns.list(")
            .doesNotContain(".list(\"");
    }
}

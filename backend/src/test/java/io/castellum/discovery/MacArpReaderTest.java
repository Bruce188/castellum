package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioural tests for {@link MacArpReader}. Exercises the static {@code parse} fixture
 * plus one launcher failure path; never touches the real {@code arp} binary.
 */
class MacArpReaderTest {

    private static final String FIXTURE_TYPICAL = """
        ? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]
        ? (192.168.1.50) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
        ? (192.168.1.100) at de:ad:be:ef:00:0a on en1 ifscope permanent [ethernet]
        """;

    @Test
    void parse_typicalArpAnOutput_returnsNeighborsWithIfaceField() {
        List<DiscoveredNeighbor> result = MacArpReader.parse(FIXTURE_TYPICAL);

        assertThat(result).hasSize(3);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.1");
        assertThat(result.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:01");
        assertThat(result.get(0).iface()).isEqualTo("en0");
        assertThat(result.get(2).iface()).isEqualTo("en1");
    }

    @Test
    void parse_singleHexOctetMacPadsToTwo() {
        // BSD arp -an sometimes emits single-hex-digit octets when the high nibble is 0
        String singleHex = "? (10.0.0.1) at 0:1:b:23:4:f on en0 ifscope [ethernet]\n";
        List<DiscoveredNeighbor> result = MacArpReader.parse(singleHex);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).macAddress()).isEqualTo("00:01:0b:23:04:0f");
    }

    @Test
    void parse_incompleteEntryQuestionMarkSkipped() {
        String mixed = """
            ? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]
            ? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
            ? (192.168.1.2) at aa:bb:cc:dd:ee:02 on en0 ifscope [ethernet]
            """;
        List<DiscoveredNeighbor> result = MacArpReader.parse(mixed);

        assertThat(result).hasSize(2);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.1");
        assertThat(result.get(1).ipAddress()).isEqualTo("192.168.1.2");
    }

    @Test
    void read_processFailsToStart_throwsDiscoveryUnavailableException() {
        Function<List<String>, Process> failingLauncher = args -> {
            throw new RuntimeException(new IOException("arp not on PATH"));
        };
        MacArpReader reader = new MacArpReader(failingLauncher);

        assertThatThrownBy(reader::read)
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("arp -an");
    }

    @Test
    void parse_emptyInput_returnsEmptyList() {
        assertThat(MacArpReader.parse(null)).isEmpty();
        assertThat(MacArpReader.parse("")).isEmpty();
        assertThat(MacArpReader.parse("   \n\n")).isEmpty();
    }
}

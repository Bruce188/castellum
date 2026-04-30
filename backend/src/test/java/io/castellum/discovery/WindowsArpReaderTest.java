package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioural tests for {@link WindowsArpReader}. Avoids invoking the real {@code arp}
 * binary by exercising the static {@link WindowsArpReader#parse} fixture on inline
 * stdout strings, plus one launcher test using a stub {@link Function}.
 */
class WindowsArpReaderTest {

    private static final String FIXTURE_THREE_ROWS = """
        Interface: 192.168.1.10 --- 0xb
          Internet Address      Physical Address      Type
          192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
          192.168.1.50          11-22-33-44-55-66     dynamic
          192.168.1.255         ff-ff-ff-ff-ff-ff     static
        """;

    @Test
    void parse_threeRowsOfDynamicAndStaticEntries_returnsAllThreeNeighbors() {
        List<DiscoveredNeighbor> result = WindowsArpReader.parse(FIXTURE_THREE_ROWS);

        assertThat(result).hasSize(3);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.1");
        assertThat(result.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:01");
        assertThat(result.get(0).hwType()).isEqualTo("dynamic");
        assertThat(result.get(2).hwType()).isEqualTo("static");
    }

    @Test
    void parse_emptyTable_returnsEmptyList() {
        String onlyHeader = """
            Interface: 192.168.1.10 --- 0xb
              Internet Address      Physical Address      Type
            """;
        assertThat(WindowsArpReader.parse(onlyHeader)).isEmpty();
        assertThat(WindowsArpReader.parse("")).isEmpty();
        assertThat(WindowsArpReader.parse(null)).isEmpty();
    }

    @Test
    void parse_macAddressNormalizedFromDashedToColonSeparated() {
        String single = "  10.0.0.1            DE-AD-BE-EF-00-01     dynamic\n";
        List<DiscoveredNeighbor> result = WindowsArpReader.parse(single);

        assertThat(result).hasSize(1);
        // Normalized: lowercase hex, colon separators
        assertThat(result.get(0).macAddress()).isEqualTo("de:ad:be:ef:00:01");
    }

    @Test
    void parse_unparseableLineSkippedWithWarning() {
        String mixed = """
            garbage line that does not match
              192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
            another junk line
              192.168.1.2           aa-bb-cc-dd-ee-02     dynamic
            """;
        List<DiscoveredNeighbor> result = WindowsArpReader.parse(mixed);
        assertThat(result).hasSize(2);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.1");
        assertThat(result.get(1).ipAddress()).isEqualTo("192.168.1.2");
    }

    @Test
    void read_processFailsToStart_throwsDiscoveryUnavailableException() {
        Function<List<String>, Process> failingLauncher = args -> {
            throw new RuntimeException(new IOException("arp not on PATH"));
        };
        WindowsArpReader reader = new WindowsArpReader(failingLauncher);

        assertThatThrownBy(reader::read)
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("arp -a");
    }

    @Test
    void read_processSucceeds_returnsParsedNeighbors() throws Exception {
        Function<List<String>, Process> successLauncher = args -> new StubProcess(FIXTURE_THREE_ROWS);
        WindowsArpReader reader = new WindowsArpReader(successLauncher);

        List<DiscoveredNeighbor> result = reader.read();
        assertThat(result).hasSize(3);
    }

    /** Minimal stub Process — returns canned stdout, exits 0 immediately. */
    private static final class StubProcess extends Process {
        private final InputStream stdout;
        StubProcess(String text) {
            this.stdout = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
        }
        @Override public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }
        @Override public InputStream getInputStream() { return stdout; }
        @Override public InputStream getErrorStream() { return InputStream.nullInputStream(); }
        @Override public int waitFor() { return 0; }
        @Override public boolean waitFor(long t, TimeUnit u) { return true; }
        @Override public int exitValue() { return 0; }
        @Override public void destroy() { }
    }
}

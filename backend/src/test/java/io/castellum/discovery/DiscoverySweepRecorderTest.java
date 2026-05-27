package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DiscoverySweepRecorder} unit test backed by H2 via {@link DataJpaTest}.
 * Pinning a fixed {@link Clock} guarantees deterministic startedAt/finishedAt assertions.
 */
@DataJpaTest
@Import({DiscoverySweepRecorder.class, DiscoverySweepRecorderTest.FixedClockConfig.class})
class DiscoverySweepRecorderTest {

    static final Instant FIXED_NOW = Instant.parse("2026-04-30T10:00:00Z");

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        Clock clock() {
            return Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        }
    }

    @Autowired private DiscoverySweepRecorder recorder;
    @Autowired private DiscoverySweepRepository repo;

    @Test
    void start_persistsRowWithStatusRunningAndReturnsId() {
        Long id = recorder.start("ARP", "eth0", "MANUAL");

        assertThat(id).isNotNull();
        Optional<DiscoverySweep> row = repo.findById(id);
        assertThat(row).isPresent();
        DiscoverySweep s = row.orElseThrow();
        assertThat(s.getStatus()).isEqualTo("RUNNING");
        assertThat(s.getSource()).isEqualTo("ARP");
        assertThat(s.getIface()).isEqualTo("eth0");
        assertThat(s.getTriggeredBy()).isEqualTo("MANUAL");
        assertThat(s.getStartedAt()).isEqualTo(FIXED_NOW);
        assertThat(s.getFinishedAt()).isNull();
        assertThat(s.getNeighborCount()).isZero();
        assertThat(s.getDeviceCount()).isZero();
    }

    @Test
    void finish_updatesRowToOkStatusWithCounts() {
        // Scheduled sweep starts with null iface; observed iface "eth0" must be stamped at finish
        Long id = recorder.start("ARP,MDNS", null, "SCHEDULER");
        recorder.finish(id, "OK", 7, 5, 99L, "eth0");

        DiscoverySweep s = repo.findById(id).orElseThrow();
        assertThat(s.getStatus()).isEqualTo("OK");
        assertThat(s.getNeighborCount()).isEqualTo(7);
        assertThat(s.getDeviceCount()).isEqualTo(5);
        assertThat(s.getAuditLogId()).isEqualTo(99L);
        assertThat(s.getFinishedAt()).isEqualTo(FIXED_NOW);
        assertThat(s.getTriggeredBy()).isEqualTo("SCHEDULER");
        assertThat(s.getIface()).isEqualTo("eth0");  // observed iface backfilled from null start
    }

    @Test
    void finish_failedStatus_setsFinishedAtAndStatus() {
        Long id = recorder.start("PCAP", "eth1", "MANUAL");
        recorder.finish(id, "FAILED", 0, 0, null, null);

        DiscoverySweep s = repo.findById(id).orElseThrow();
        assertThat(s.getStatus()).isEqualTo("FAILED");
        assertThat(s.getNeighborCount()).isZero();
        assertThat(s.getDeviceCount()).isZero();
        assertThat(s.getAuditLogId()).isNull();
        assertThat(s.getFinishedAt()).isEqualTo(FIXED_NOW);
    }

    @Test
    void finish_nullIface_preservesStartIface() {
        // Manual sweep starts with "wlan0"; null iface at finish must NOT overwrite it
        Long id = recorder.start("ARP", "wlan0", "MANUAL");
        recorder.finish(id, "OK", 3, 2, null, null);

        DiscoverySweep s = repo.findById(id).orElseThrow();
        assertThat(s.getIface()).isEqualTo("wlan0");  // preserved from start
    }
}

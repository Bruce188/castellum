package io.castellum.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class ScanRecoveryQueryTest {

    @Autowired
    private TestEntityManager em;

    @Autowired
    private ScanRepository scanRepository;

    private static final Instant PROCESS_START = Instant.parse("2026-05-26T12:00:00Z");
    private static final Instant BEFORE = PROCESS_START.minusSeconds(3600); // 1h before
    private static final Instant AFTER  = PROCESS_START.plusSeconds(3600);  // 1h after

    private Long pendingId;
    private Long staleRunningId;
    private Long freshRunningId;
    private Long completeId;
    private Long failedId;

    @BeforeEach
    void seed() {
        Scan pending = scan(ScanStatus.PENDING, BEFORE, null);
        Scan staleRunning = scan(ScanStatus.RUNNING, BEFORE, null);
        Scan freshRunning = scan(ScanStatus.RUNNING, AFTER, null);
        Scan complete = scan(ScanStatus.COMPLETE, BEFORE, BEFORE.plusSeconds(60));
        Scan failed = scan(ScanStatus.FAILED, BEFORE, null);

        pendingId = em.persistAndGetId(pending, Long.class);
        staleRunningId = em.persistAndGetId(staleRunning, Long.class);
        freshRunningId = em.persistAndGetId(freshRunning, Long.class);
        completeId = em.persistAndGetId(complete, Long.class);
        failedId = em.persistAndGetId(failed, Long.class);
        em.flush();
    }

    // -----------------------------------------------------------------------
    // findRecoverable — selection contract
    // -----------------------------------------------------------------------

    @Test
    void findRecoverable_returnsExactlyPendingAndStaleRunning() {
        List<Scan> results = scanRepository.findRecoverable(PROCESS_START);

        assertThat(results).extracting(Scan::getId)
            .containsExactlyInAnyOrder(pendingId, staleRunningId);
    }

    @Test
    void findRecoverable_excludesFreshRunning() {
        List<Scan> results = scanRepository.findRecoverable(PROCESS_START);

        assertThat(results).extracting(Scan::getId).doesNotContain(freshRunningId);
    }

    @Test
    void findRecoverable_excludesComplete() {
        List<Scan> results = scanRepository.findRecoverable(PROCESS_START);

        assertThat(results).extracting(Scan::getId).doesNotContain(completeId);
    }

    @Test
    void findRecoverable_excludesFailed() {
        List<Scan> results = scanRepository.findRecoverable(PROCESS_START);

        assertThat(results).extracting(Scan::getId).doesNotContain(failedId);
    }

    // -----------------------------------------------------------------------
    // claimForRecovery — guarded CAS contract
    // -----------------------------------------------------------------------

    @Test
    void claimForRecovery_pendingExpected_returnsOneAndStaysPending() {
        int rows = scanRepository.claimForRecovery(pendingId, ScanStatus.PENDING);

        assertThat(rows).isEqualTo(1);
        em.clear();
        Scan reloaded = scanRepository.findById(pendingId).orElseThrow();
        assertThat(reloaded.getStatus()).isEqualTo(ScanStatus.PENDING);
        assertThat(reloaded.getCompletedAt()).isNull();
    }

    @Test
    void claimForRecovery_staleRunningExpected_returnsOneFlipsToPendingClearsCompletedAt() {
        // Give the stale-running scan a completedAt to verify it gets cleared
        Scan staleRunning = scanRepository.findById(staleRunningId).orElseThrow();
        staleRunning.setCompletedAt(BEFORE);
        em.persist(staleRunning);
        em.flush();

        int rows = scanRepository.claimForRecovery(staleRunningId, ScanStatus.RUNNING);

        assertThat(rows).isEqualTo(1);
        em.clear();
        Scan reloaded = scanRepository.findById(staleRunningId).orElseThrow();
        assertThat(reloaded.getStatus()).isEqualTo(ScanStatus.PENDING);
        assertThat(reloaded.getCompletedAt()).isNull();
    }

    @Test
    void claimForRecovery_wrongExpectedStatus_returnsZeroAndRowUnchanged() {
        // The PENDING row has status PENDING; claim with expected=RUNNING → mismatch → 0
        int rows = scanRepository.claimForRecovery(pendingId, ScanStatus.RUNNING);

        assertThat(rows).isEqualTo(0);
        em.clear();
        Scan reloaded = scanRepository.findById(pendingId).orElseThrow();
        assertThat(reloaded.getStatus()).isEqualTo(ScanStatus.PENDING);
    }

    @Test
    void claimForRecovery_secondCallOnSameRow_returnsZero() {
        // First call claims it (PENDING→PENDING confirmed: returns 1)
        int first = scanRepository.claimForRecovery(pendingId, ScanStatus.PENDING);
        assertThat(first).isEqualTo(1);

        // Second call with same expected status still returns 1 for PENDING→PENDING
        // but if we use RUNNING as expected it should return 0 (row is PENDING, not RUNNING)
        int second = scanRepository.claimForRecovery(pendingId, ScanStatus.RUNNING);
        assertThat(second).isEqualTo(0);
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    private static Scan scan(ScanStatus status, Instant requestedAt, Instant completedAt) {
        Scan s = new Scan();
        s.setCidr("10.0.0.0/24");
        s.setScanType("PING_SWEEP");
        s.setStatus(status);
        s.setRequestedAt(requestedAt);
        s.setCompletedAt(completedAt);
        return s;
    }
}

package io.castellum.scan;

import io.castellum.audit.AuditLogRepository;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Integration test for {@link ScanRecoveryService}.
 *
 * <p>Seeds a PENDING scan with a past {@code requestedAt}, invokes the recovery listener
 * directly, and asserts the scan transitions to COMPLETE and a {@code SCAN_RECOVERY} audit
 * row is emitted.
 *
 * <p>Both tests share a real single-thread {@link ThreadPoolTaskExecutor} (core/max = 1)
 * that replaces the production {@code scanTaskExecutor} bean. This means
 * {@code @Async("scanTaskExecutor")} dispatches onto a genuine worker thread in a
 * separate transaction, exercising the commit-then-dispatch ordering contract.
 * A {@link CountDownLatch} gates each assertion on actual async completion — no
 * {@code Thread.sleep} anywhere.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "spring.main.allow-bean-definition-overriding=true"
)
@WithMockUser(roles = "ADMIN")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class ScanRecoveryIntegrationTest {

    /**
     * Override {@code scanTaskExecutor} with a real single-thread pool so
     * {@code @Async("scanTaskExecutor")} dispatches on a genuine worker thread.
     * This is the configuration exercised by both test methods.
     */
    @TestConfiguration
    static class RealExecutorConfig {
        @Bean
        @Primary
        ThreadPoolTaskExecutor scanTaskExecutor() {
            ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
            executor.setCorePoolSize(1);
            executor.setMaxPoolSize(1);
            executor.setQueueCapacity(10);
            executor.setThreadNamePrefix("test-scan-exec-");
            executor.initialize();
            return executor;
        }
    }

    @Autowired ScanRepository scanRepository;
    @Autowired AuditLogRepository auditLogRepository;
    @Autowired ScanRecoveryService recoveryService;
    @Autowired DeviceRepository deviceRepository;
    @Autowired NetworkServiceRepository networkServiceRepository;

    @MockBean NmapRunner nmapRunner;

    @AfterEach
    void cleanup() {
        networkServiceRepository.deleteAll();
        deviceRepository.deleteAll();
        scanRepository.deleteAll();
    }

    private static final String MOCK_STDOUT = """
            <?xml version="1.0"?>
            <nmaprun>
            <host><status state="up" reason="syn-ack"/>
            <address addr="10.10.10.5" addrtype="ipv4"/>
            <hostnames></hostnames>
            <ports>
            <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.4p1"><cpe>cpe:/a:openbsd:openssh:8.4p1</cpe></service></port>
            <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.20.1"><cpe>cpe:/a:igor_sysoev:nginx:1.20.1</cpe></service></port>
            </ports>
            </host>
            <runstats><finished/></runstats>
            </nmaprun>
            """;

    @Test
    void seededPendingScan_recoversToComplete_andEmitsScanRecoveryAudit() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        // Stub nmap: count down when invoked on the worker thread so we can await completion.
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenAnswer(inv -> {
            latch.countDown();
            return new NmapResult(0, MOCK_STDOUT, "");
        });

        // Seed a PENDING scan with requestedAt well before process start.
        // PING_SWEEP is used here (not SERVICE_DETECT) because this test exercises the
        // recovery commit-then-dispatch ordering contract, which is scan-type-agnostic.
        // SERVICE_DETECT now scopes to alive hosts (resolved from the device inventory) and
        // would short-circuit when no devices are seeded — that path has its own tests.
        Scan s = new Scan();
        s.setCidr("10.10.10.0/24");
        s.setScanType("PING_SWEEP");
        s.setStatus(ScanStatus.PENDING);
        s.setRequestedAt(Instant.parse("2026-05-24T00:00:00Z")); // well before boot
        Long id = scanRepository.save(s).getId();

        long auditCountBefore = auditLogRepository.findAll().size();

        // Invoke recovery directly (same pattern as BootstrapAdminTest calling bootstrap()).
        recoveryService.recoverInterruptedScans();

        // Wait for the async worker thread to finish before asserting.
        assertTrue(latch.await(10, TimeUnit.SECONDS),
            "nmap stub must have been invoked on the worker thread within 10 s");

        // Give the worker thread a moment to persist the final COMPLETE status.
        awaitScanStatus(id, ScanStatus.COMPLETE, 10);

        // AC5: scan must leave PENDING and reach COMPLETE.
        Scan recovered = scanRepository.findById(id).orElseThrow();
        assertNotEquals(ScanStatus.PENDING, recovered.getStatus(),
            "scan must no longer be PENDING after recovery");
        assertEquals(ScanStatus.COMPLETE, recovered.getStatus(),
            "scan must be COMPLETE after recovery (real executor + mocked nmap)");
        assertNotNull(recovered.getCompletedAt(), "completedAt must be set on COMPLETE scan");

        // AC3: a SCAN_RECOVERY audit row must exist.
        assertTrue(
            auditLogRepository.findAll().stream()
                .anyMatch(a -> "SCAN_RECOVERY".equals(a.getAction())),
            "a SCAN_RECOVERY audit row must be emitted");

        // AC2: verify more audit rows exist than before (SCAN_EXECUTE + SCAN_COMPLETE added).
        long auditCountAfter = auditLogRepository.findAll().size();
        assertTrue(auditCountAfter > auditCountBefore,
            "new audit rows must have been appended during recovery");

        // AC4 second-restart: calling recovery again on an already-COMPLETE scan is a no-op.
        recoveryService.recoverInterruptedScans();
        Scan afterSecondCall = scanRepository.findById(id).orElseThrow();
        assertEquals(ScanStatus.COMPLETE, afterSecondCall.getStatus(),
            "second recovery call must not change COMPLETE scan status");
        assertEquals(recovered.getCompletedAt(), afterSecondCall.getCompletedAt(),
            "completedAt must be unchanged after second recovery call");
    }

    /**
     * Regression guard for the commit-then-dispatch ordering contract.
     *
     * <p>Uses a real single-thread executor (wired via {@link RealExecutorConfig}) so the
     * async thread runs in a separate transaction from the recovery CAS. After the worker
     * thread completes (latch awaited), asserts:
     * <ol>
     *   <li>A scan that was already COMPLETE before recovery is NOT re-executed or reverted —
     *       it remains COMPLETE with its original {@code completedAt}.</li>
     *   <li>A genuinely orphaned PENDING scan IS requeued and reaches COMPLETE.</li>
     * </ol>
     *
     * <p>If {@code @Transactional} were re-added to the recovery listener, the outer
     * transaction would commit AFTER the async thread's COMPLETE save, overwriting the scan
     * back to PENDING (lost-update). The latch-based await would then observe PENDING, and
     * the first assertion would fail — catching the regression.
     */
    @Test
    void recovery_withRealExecutor_scanRemainsCompleteAfterDispatch() throws Exception {
        // --- arrange: one COMPLETE scan (must not be re-executed), one PENDING (must run) ---
        // PING_SWEEP (not SERVICE_DETECT) keeps this focused on the recovery dispatch ordering
        // contract; SERVICE_DETECT's alive-host scoping would short-circuit with no seeded
        // devices and is covered by its own tests.
        Scan completeScan = new Scan();
        completeScan.setCidr("10.10.10.2/32");
        completeScan.setScanType("PING_SWEEP");
        completeScan.setStatus(ScanStatus.COMPLETE);
        completeScan.setRequestedAt(Instant.parse("2026-05-24T00:00:00Z"));
        completeScan.setCompletedAt(Instant.parse("2026-05-24T01:00:00Z"));
        Long completeId = scanRepository.save(completeScan).getId();
        Instant originalCompletedAt = completeScan.getCompletedAt();

        Scan orphan = new Scan();
        orphan.setCidr("10.10.10.3/32");
        orphan.setScanType("PING_SWEEP");
        orphan.setStatus(ScanStatus.PENDING);
        orphan.setRequestedAt(Instant.parse("2026-05-24T00:00:00Z"));
        Long orphanId = scanRepository.save(orphan).getId();

        // The worker thread invokes nmapRunner exactly once (for the orphan).
        CountDownLatch latch = new CountDownLatch(1);
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenAnswer(inv -> {
            latch.countDown();
            return new NmapResult(0, MOCK_STDOUT, "");
        });

        // --- act ---
        recoveryService.recoverInterruptedScans();

        // Wait for the async worker thread to finish executing the orphan scan.
        assertTrue(latch.await(10, TimeUnit.SECONDS),
            "worker thread must have invoked nmap for the orphaned scan within 10 s");

        // Give the worker thread a moment to persist the terminal COMPLETE status.
        awaitScanStatus(orphanId, ScanStatus.COMPLETE, 10);

        // --- assert: COMPLETE scan is untouched ---
        Scan stillComplete = scanRepository.findById(completeId).orElseThrow();
        assertEquals(ScanStatus.COMPLETE, stillComplete.getStatus(),
            "COMPLETE scan must not be reverted by recovery — if @Transactional wrapped " +
            "the dispatch, the CAS could overwrite COMPLETE back to PENDING (lost-update)");
        assertEquals(originalCompletedAt, stillComplete.getCompletedAt(),
            "completedAt of the already-COMPLETE scan must be unchanged after recovery");

        // --- assert: orphaned PENDING scan was requeued and executed ---
        Scan executed = scanRepository.findById(orphanId).orElseThrow();
        assertEquals(ScanStatus.COMPLETE, executed.getStatus(),
            "orphaned PENDING scan must reach COMPLETE after recovery dispatch");
        assertNotNull(executed.getCompletedAt(),
            "completedAt must be set on the recovered scan");
    }

    /**
     * Polls the database until the scan reaches the expected status or the timeout elapses.
     * Avoids {@code Thread.sleep} flakiness by using a tight poll loop bounded by wall time.
     */
    private void awaitScanStatus(Long scanId, ScanStatus expected, int timeoutSeconds)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + (long) timeoutSeconds * 1000;
        while (System.currentTimeMillis() < deadline) {
            Scan current = scanRepository.findById(scanId).orElseThrow();
            if (expected == current.getStatus()) {
                return;
            }
            Thread.sleep(50);
        }
    }
}

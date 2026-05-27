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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Instant;
import java.util.concurrent.Executor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Integration test for {@link ScanRecoveryService}.
 *
 * <p>Seeds a PENDING scan with a past {@code requestedAt}, invokes the recovery listener
 * directly, and asserts the scan transitions to COMPLETE and a {@code SCAN_RECOVERY} audit
 * row is emitted. Uses a {@link SyncTaskExecutor} override and a mocked {@link NmapRunner}
 * to make execution deterministic without real nmap.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "spring.main.allow-bean-definition-overriding=true"
)
@WithMockUser(roles = "ADMIN")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class ScanRecoveryIntegrationTest {

    /**
     * Override {@code scanTaskExecutor} with a synchronous executor so
     * {@code @Async("scanTaskExecutor")} runs inline on the calling thread.
     */
    @TestConfiguration
    static class SyncExecutorConfig {
        @Bean
        @Primary
        @Qualifier("scanTaskExecutor")
        Executor scanTaskExecutor() {
            return new SyncTaskExecutor();
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

    @Test
    void seededPendingScan_recoversToComplete_andEmitsScanRecoveryAudit() throws Exception {
        // Stub NmapRunner with minimal single-host stdout (mirrors ScanExecutionIntegrationTest)
        String mockStdout = """
                Nmap scan report for 10.10.10.5
                Host is up (0.0010s latency).
                PORT   STATE SERVICE VERSION
                22/tcp open  ssh     OpenSSH 8.4p1
                80/tcp open  http    nginx 1.20.1
                """;
        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, mockStdout, ""));

        // Seed a PENDING scan with requestedAt well before process start
        Scan s = new Scan();
        s.setCidr("10.10.10.0/24");
        s.setScanType("SERVICE_DETECT");
        s.setStatus(ScanStatus.PENDING);
        s.setRequestedAt(Instant.parse("2026-05-24T00:00:00Z")); // well before boot
        Long id = scanRepository.save(s).getId();

        long auditCountBefore = auditLogRepository.findAll().size();

        // Invoke recovery directly (same pattern as BootstrapAdminTest calling bootstrap())
        recoveryService.recoverInterruptedScans();

        // AC5: scan must leave PENDING and reach COMPLETE
        Scan recovered = scanRepository.findById(id).orElseThrow();
        assertNotEquals(ScanStatus.PENDING, recovered.getStatus(),
            "scan must no longer be PENDING after recovery");
        assertEquals(ScanStatus.COMPLETE, recovered.getStatus(),
            "scan must be COMPLETE after recovery (SyncTaskExecutor + mocked nmap)");
        assertNotNull(recovered.getCompletedAt(), "completedAt must be set on COMPLETE scan");

        // AC3: a SCAN_RECOVERY audit row must exist
        assertTrue(
            auditLogRepository.findAll().stream()
                .anyMatch(a -> "SCAN_RECOVERY".equals(a.getAction())),
            "a SCAN_RECOVERY audit row must be emitted");

        // AC2: verify more audit rows exist than before (SCAN_EXECUTE + SCAN_COMPLETE added)
        long auditCountAfter = auditLogRepository.findAll().size();
        assertTrue(auditCountAfter > auditCountBefore,
            "new audit rows must have been appended during recovery");

        // AC4 second-restart: calling recovery again on an already-COMPLETE scan is a no-op
        recoveryService.recoverInterruptedScans();
        Scan afterSecondCall = scanRepository.findById(id).orElseThrow();
        assertEquals(ScanStatus.COMPLETE, afterSecondCall.getStatus(),
            "second recovery call must not change COMPLETE scan status");
        assertEquals(recovered.getCompletedAt(), afterSecondCall.getCompletedAt(),
            "completedAt must be unchanged after second recovery call");
    }
}

package io.castellum.scan;

import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditLogRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.Executor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end integration test for the controller-to-async scan wiring.
 *
 * <p>The {@code scanTaskExecutor} is overridden with a {@link SyncTaskExecutor} so the
 * {@code @Async} body runs inline on the request thread — making assertions deterministic
 * without flaky latch/sleep patterns.
 *
 * <p>An alternative approach (kept as a comment for future reviewers) is to use a
 * {@code CountDownLatch} + {@code await()} with a real {@link org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor};
 * the sync override is simpler and avoids flake.
 *
 * <p>{@link NmapRunner} is mocked so no actual nmap binary is required.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "spring.main.allow-bean-definition-overriding=true"
)
@AutoConfigureMockMvc
@WithMockUser(roles = "ADMIN")
// Dirty the context so the allow-bean-definition-overriding=true context is not reused
// by other tests that share the default context (avoids H2 schema-not-found pollution).
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class ScanExecutionIntegrationTest {

    /**
     * Override {@code scanTaskExecutor} with a synchronous executor so
     * {@code @Async("scanTaskExecutor")} runs inline on the request thread.
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

    @Autowired MockMvc mockMvc;
    @Autowired ScanRepository scanRepository;
    @Autowired DeviceRepository deviceRepository;
    @Autowired NetworkServiceRepository networkServiceRepository;
    @Autowired AuditLogRepository auditLogRepository;
    @Autowired ObjectMapper objectMapper;

    // Mock NmapRunner so no real nmap binary is invoked.
    @MockBean NmapRunner nmapRunner;

    @AfterEach
    void cleanup() {
        networkServiceRepository.deleteAll();
        deviceRepository.deleteAll();
        // AuditLogRepository is append-only — no deleteAll exposed.
        // Tests use list-size snapshots instead.
    }

    // -----------------------------------------------------------------------
    // Test 1: success path — COMPLETE + devices + services + audit rows
    // -----------------------------------------------------------------------

    @Test
    void postScan_completesAsync_persistsDevicesAndServices() throws Exception {
        // SERVICE_DETECT is now scoped to alive hosts within the CIDR. Seed one live device
        // (as a prior PING_SWEEP would have) so the alive-host resolver yields a target;
        // without it the scan short-circuits to COMPLETE with zero services.
        Device seeded = new Device(null, "10.10.10.5", null, null,
            java.time.Instant.now(), java.time.Instant.now());
        deviceRepository.save(seeded);

        // One host, two services in the mock stdout (nmap -oX - XML).
        String mockStdout = """
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
        // Alive-host path uses the explicit-host-list overload.
        when(nmapRunner.run(anyList(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, mockStdout, ""));

        // Capture audit rows before the request.
        List<AuditLog> auditBefore = auditLogRepository.findAll();

        // POST /api/scan
        MvcResult mvcResult = mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.10.10.0/24\",\"type\":\"SERVICE_DETECT\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").isNumber())
            .andReturn();

        // Extract scan id from response
        String responseBody = mvcResult.getResponse().getContentAsString();
        Long scanId = objectMapper.readTree(responseBody).get("id").asLong();

        // Because SyncTaskExecutor runs the @Async body inline, the scan is COMPLETE now.
        Scan scan = scanRepository.findById(scanId).orElseThrow();
        assertEquals(ScanStatus.COMPLETE, scan.getStatus(),
            "scan must be COMPLETE after sync async execution");
        assertNotNull(scan.getCompletedAt(), "completedAt must be set");
        assertNull(scan.getFailureReason(), "failureReason must be null on success path");

        // At least one Device row must exist.
        List<Device> devices = deviceRepository.findAll();
        assertFalse(devices.isEmpty(), "at least one Device must be persisted");
        boolean hasExpectedIp = devices.stream().anyMatch(d -> "10.10.10.5".equals(d.getIpAddress()));
        assertTrue(hasExpectedIp, "Device with IP 10.10.10.5 must exist");

        // Exactly 2 NetworkService rows for device 10.10.10.5 (22/tcp ssh + 80/tcp http).
        Device device10 = devices.stream()
            .filter(d -> "10.10.10.5".equals(d.getIpAddress()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("Device 10.10.10.5 not found"));
        List<NetworkService> allServices = networkServiceRepository.findAll();
        List<NetworkService> services = allServices.stream()
            .filter(s -> device10.getId().equals(s.getDeviceId()))
            .toList();
        assertEquals(2, services.size(),
            "exactly 2 NetworkService rows must be persisted for device 10.10.10.5; got " + services.size());

        // Assert 22/tcp ssh row with OpenSSH product + CPE 2.3 string.
        NetworkService sshRow = services.stream()
            .filter(s -> s.getPort() == 22 && "tcp".equals(s.getProtocol()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("22/tcp row not found in " + services));
        // When nmap fingerprints the service with product="OpenSSH", the display name becomes
        // the product string and the stored product is lowercased for NVD-map lookup.
        assertEquals("OpenSSH", sshRow.getName(), "22/tcp name must be the nmap product 'OpenSSH'");
        assertEquals("openssh", sshRow.getProduct(),
            "22/tcp product must be lowercased 'openssh'; got: " + sshRow.getProduct());
        assertEquals("8.4p1", sshRow.getVersion(),
            "22/tcp version must be nmap's verbatim string; got: " + sshRow.getVersion());
        assertEquals("cpe:2.3:a:openbsd:openssh:8.4p1:*:*:*:*:*:*:*", sshRow.getCpe(),
            "22/tcp cpe must be the converted CPE 2.3 string; got: " + sshRow.getCpe());

        // Assert 80/tcp http row with nginx product + CPE.
        NetworkService httpRow = services.stream()
            .filter(s -> s.getPort() == 80 && "tcp".equals(s.getProtocol()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("80/tcp row not found in " + services));
        assertEquals("nginx", httpRow.getName(), "80/tcp name must be the nmap product 'nginx'");
        assertEquals("nginx", httpRow.getProduct(), "80/tcp product must be lowercased 'nginx'");
        assertEquals("cpe:2.3:a:igor_sysoev:nginx:1.20.1:*:*:*:*:*:*:*", httpRow.getCpe(),
            "80/tcp cpe must be the converted CPE 2.3 string; got: " + httpRow.getCpe());

        // Audit events: SCAN_SUBMIT + SCAN_EXECUTE + SCAN_COMPLETE = 3 new rows.
        List<AuditLog> auditAfter = auditLogRepository.findAll();
        long newAuditRows = auditAfter.size() - auditBefore.size();
        assertTrue(newAuditRows >= 3,
            "at least SCAN_SUBMIT + SCAN_EXECUTE + SCAN_COMPLETE audit rows must exist; got " + newAuditRows);
    }

    // -----------------------------------------------------------------------
    // Test 2: failure path — FAILED + failureReason + SCAN_FAILED audit
    // -----------------------------------------------------------------------

    @Test
    void postScan_nmapRunnerThrows_scanEndsWithFailedAndAudit() throws Exception {
        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenThrow(new IOException("boom"));

        List<AuditLog> auditBefore = auditLogRepository.findAll();

        MvcResult mvcResult = mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.10.20.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").isNumber())
            .andReturn();

        Long scanId = objectMapper.readTree(
            mvcResult.getResponse().getContentAsString()).get("id").asLong();

        // Scan must end in FAILED with failureReason containing "boom".
        Scan scan = scanRepository.findById(scanId).orElseThrow();
        assertEquals(ScanStatus.FAILED, scan.getStatus(),
            "scan must be FAILED when NmapRunner throws");
        assertNotNull(scan.getFailureReason(), "failureReason must be populated");
        assertTrue(scan.getFailureReason().contains("boom"),
            "failureReason must contain the exception message 'boom'");
        assertNotNull(scan.getCompletedAt(), "completedAt must be set on FAILED path");

        // SCAN_FAILED audit row must exist.
        List<AuditLog> auditAfter = auditLogRepository.findAll();
        long newAuditRows = auditAfter.size() - auditBefore.size();
        assertTrue(newAuditRows >= 2,
            "at least SCAN_SUBMIT + SCAN_FAILED audit rows must exist; got " + newAuditRows);
    }
}

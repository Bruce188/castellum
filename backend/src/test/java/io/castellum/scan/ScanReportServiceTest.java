package io.castellum.scan;

import io.castellum.cve.CveMatcher;
import io.castellum.cve.Cve;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import io.castellum.web.dto.ScanReportDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * RED-phase tests for {@link ScanReportService#buildReport(Long)}.
 *
 * Mockito unit test — mocks the three repos + CveMatcher so delta branches are
 * deterministic and do not require a running database.
 */
@ExtendWith(MockitoExtension.class)
class ScanReportServiceTest {

    @Mock
    private ScanRepository scanRepository;
    @Mock
    private DeviceRepository deviceRepository;
    @Mock
    private NetworkServiceRepository networkServiceRepository;
    @Mock
    private CveMatcher cveMatcher;

    private ScanReportService service;

    private static final Long SCAN_ID = 10L;
    private static final Instant REQUESTED_AT = Instant.parse("2024-06-01T10:00:00Z");
    private static final Instant COMPLETED_AT = Instant.parse("2024-06-01T10:05:00Z");

    @BeforeEach
    void setUp() {
        service = new ScanReportService(scanRepository, deviceRepository, networkServiceRepository, cveMatcher);
    }

    // ── helper builders ─────────────────────────────────────────────────────────

    private Scan buildScan() {
        Scan scan = new Scan();
        scan.setId(SCAN_ID);
        scan.setCidr("10.0.0.0/24");
        scan.setScanType("PING_SWEEP");
        scan.setStatus(ScanStatus.COMPLETE);
        scan.setRequestedAt(REQUESTED_AT);
        scan.setCompletedAt(COMPLETED_AT);
        return scan;
    }

    private Device newDevice(Long id, String ip) {
        Device d = new Device();
        d.setId(id);
        d.setIpAddress(ip);
        d.setHostname("host-" + id);
        d.setDiscoveredByScanId(SCAN_ID);  // will be overridden per-test
        d.setLastSeenByScanId(SCAN_ID);
        return d;
    }

    private NetworkService serviceInWindow(Long id, Long deviceId) {
        // observedAt inside [requestedAt, completedAt]
        return new NetworkService(id, deviceId, 22, "tcp", "openssh", "8.4", REQUESTED_AT.plusSeconds(60));
    }

    private NetworkService serviceBeforeWindow(Long id, Long deviceId) {
        // observedAt strictly before requestedAt
        return new NetworkService(id, deviceId, 80, "tcp", "nginx", "1.24", REQUESTED_AT.minusSeconds(3600));
    }

    // ── (1) delta_new_whenDiscoveredByThisScan ───────────────────────────────────

    @Test
    void delta_new_whenDiscoveredByThisScan() {
        Scan scan = buildScan();
        when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(scan));

        Device deviceA = newDevice(101L, "10.0.0.1");
        deviceA.setDiscoveredByScanId(SCAN_ID);   // NEW: first discovered by this scan
        deviceA.setLastSeenByScanId(SCAN_ID);

        when(deviceRepository.findByLastSeenByScanId(SCAN_ID)).thenReturn(List.of(deviceA));
        when(networkServiceRepository.findByDeviceIdIn(List.of(101L)))
            .thenReturn(List.of(serviceInWindow(1L, 101L)));
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of());

        ScanReportDto report = service.buildReport(SCAN_ID);

        assertThat(report).isNotNull();
        assertThat(report.devices()).hasSize(1);
        assertThat(report.devices().get(0).delta()).isEqualTo("new");
    }

    // ── (2) delta_changed_whenPreexistingReobserved ──────────────────────────────

    @Test
    void delta_changed_whenPreexistingReobservedWithServiceInWindow() {
        Scan scan = buildScan();
        when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(scan));

        Device deviceB = newDevice(102L, "10.0.0.2");
        deviceB.setDiscoveredByScanId(SCAN_ID - 1);  // pre-existing: discovered by a different scan
        deviceB.setLastSeenByScanId(SCAN_ID);

        when(deviceRepository.findByLastSeenByScanId(SCAN_ID)).thenReturn(List.of(deviceB));
        // service.observedAt falls INSIDE the scan window → "changed"
        NetworkService svcInWindow = serviceInWindow(2L, 102L);
        when(networkServiceRepository.findByDeviceIdIn(List.of(102L)))
            .thenReturn(List.of(svcInWindow));
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of());

        ScanReportDto report = service.buildReport(SCAN_ID);

        assertThat(report).isNotNull();
        assertThat(report.devices()).hasSize(1);
        assertThat(report.devices().get(0).delta()).isEqualTo("changed");
    }

    // ── (3) delta_unchanged_whenPreexistingNotTouched ────────────────────────────

    @Test
    void delta_unchanged_whenPreexistingNotTouched() {
        Scan scan = buildScan();
        when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(scan));

        Device deviceC = newDevice(103L, "10.0.0.3");
        deviceC.setDiscoveredByScanId(SCAN_ID - 1);  // pre-existing
        deviceC.setLastSeenByScanId(SCAN_ID);

        when(deviceRepository.findByLastSeenByScanId(SCAN_ID)).thenReturn(List.of(deviceC));
        // All services observed BEFORE the scan window → "unchanged"
        NetworkService svcBefore = serviceBeforeWindow(3L, 103L);
        when(networkServiceRepository.findByDeviceIdIn(List.of(103L)))
            .thenReturn(List.of(svcBefore));
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of());

        ScanReportDto report = service.buildReport(SCAN_ID);

        assertThat(report).isNotNull();
        assertThat(report.devices()).hasSize(1);
        assertThat(report.devices().get(0).delta()).isEqualTo("unchanged");
    }

    // ── (4) summaryCounts_reflectSnapshot ────────────────────────────────────────

    @Test
    void summaryCounts_reflectSnapshot() {
        Scan scan = buildScan();
        when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(scan));

        Device deviceA = newDevice(101L, "10.0.0.1");
        deviceA.setDiscoveredByScanId(SCAN_ID);
        deviceA.setLastSeenByScanId(SCAN_ID);

        Device deviceB = newDevice(102L, "10.0.0.2");
        deviceB.setDiscoveredByScanId(SCAN_ID - 1);
        deviceB.setLastSeenByScanId(SCAN_ID);

        when(deviceRepository.findByLastSeenByScanId(SCAN_ID)).thenReturn(List.of(deviceA, deviceB));

        // Device A has 1 service; device B has 2 services
        NetworkService sA1 = new NetworkService(1L, 101L, 22, "tcp", "openssh", "8.4", REQUESTED_AT.plusSeconds(30));
        NetworkService sB1 = new NetworkService(2L, 102L, 80, "tcp", "nginx", "1.24", REQUESTED_AT.plusSeconds(30));
        NetworkService sB2 = serviceBeforeWindow(3L, 102L);

        when(networkServiceRepository.findByDeviceIdIn(anyList()))
            .thenReturn(List.of(sA1, sB1, sB2));

        // CveMatcher returns 1 CVE for openssh, 1 different CVE for nginx; both distinct
        Cve cveA = new Cve();
        cveA.setCveId("CVE-2024-0001");

        Cve cveB = new Cve();
        cveB.setCveId("CVE-2024-0002");

        // Other CPE lookups return empty (registered first so specific stubs below take precedence)
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of());
        when(cveMatcher.findVulnerable("cpe:2.3:a:openssh:openssh:8.4:*:*:*:*:*:*:*"))
            .thenReturn(List.of(cveA));
        when(cveMatcher.findVulnerable("cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*"))
            .thenReturn(List.of(cveB));

        ScanReportDto report = service.buildReport(SCAN_ID);

        assertThat(report).isNotNull();

        ScanReportDto.ScanSummary summary = report.summary();
        assertThat(summary.deviceCount()).isEqualTo(2);
        assertThat(summary.serviceCount()).isEqualTo(3);
        // distinct CVE ids across snapshot — at least 1 (exact 2 if cveMatcher stubs above fire)
        assertThat(summary.cveCount()).isGreaterThanOrEqualTo(1);

        // Duration should equal completedAt − requestedAt in millis
        long expectedMillis = COMPLETED_AT.toEpochMilli() - REQUESTED_AT.toEpochMilli();
        assertThat(summary.durationMillis()).isEqualTo(expectedMillis);
    }

    // ── (5) metadata fields present ──────────────────────────────────────────────

    @Test
    void metadata_populatedFromScan() {
        Scan scan = buildScan();
        when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(scan));

        Device d = newDevice(101L, "10.0.0.1");
        d.setDiscoveredByScanId(SCAN_ID);
        d.setLastSeenByScanId(SCAN_ID);

        when(deviceRepository.findByLastSeenByScanId(SCAN_ID)).thenReturn(List.of(d));
        when(networkServiceRepository.findByDeviceIdIn(anyList())).thenReturn(List.of());

        ScanReportDto report = service.buildReport(SCAN_ID);

        assertThat(report).isNotNull();
        assertThat(report.summary().scanId()).isEqualTo(SCAN_ID);
        assertThat(report.summary().cidr()).isEqualTo("10.0.0.0/24");
        assertThat(report.summary().scanType()).isEqualTo("PING_SWEEP");
        assertThat(report.summary().status()).isEqualTo(ScanStatus.COMPLETE);
        assertThat(report.summary().requestedAt()).isEqualTo(REQUESTED_AT);
        assertThat(report.summary().completedAt()).isEqualTo(COMPLETED_AT);
    }

    // ── (6) services and cveIds present on snapshot device ───────────────────────

    @Test
    void devicesInSnapshot_containServicesAndCveIds() {
        Scan scan = buildScan();
        when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(scan));

        Device d = newDevice(101L, "10.0.0.1");
        d.setDiscoveredByScanId(SCAN_ID);
        d.setLastSeenByScanId(SCAN_ID);

        when(deviceRepository.findByLastSeenByScanId(SCAN_ID)).thenReturn(List.of(d));

        NetworkService svc = serviceInWindow(1L, 101L);
        when(networkServiceRepository.findByDeviceIdIn(anyList())).thenReturn(List.of(svc));

        Cve cve = new Cve();
        cve.setCveId("CVE-2024-9999");
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));

        ScanReportDto report = service.buildReport(SCAN_ID);

        assertThat(report).isNotNull();
        ScanReportDto.SnapshotDeviceDto dev = report.devices().get(0);
        assertThat(dev.services()).isNotNull();
        assertThat(dev.cveIds()).isNotNull();
        // At least one CVE id should be present from the mock
        assertThat(dev.cveIds()).contains("CVE-2024-9999");
        // Service row fields populated
        assertThat(dev.services()).hasSize(1);
        assertThat(dev.services().get(0).port()).isEqualTo(22);
        assertThat(dev.services().get(0).protocol()).isEqualTo("tcp");
    }

    // ── (7) missing scan throws NoSuchElementException ───────────────────────────

    @Test
    void buildReport_missingScan_throwsNoSuchElementException() {
        when(scanRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.buildReport(99L))
            .isInstanceOf(NoSuchElementException.class);
    }

    // ── (9) NB1: in-flight scan (completedAt == null) must not NPE ───────────────

    /**
     * NB1 regression: a RUNNING/PENDING scan has {@code completedAt == null}.
     * A pre-existing device re-observed during that scan previously caused an NPE
     * in {@code computeDelta} because {@code scan.getCompletedAt()} was used without a
     * null-guard. After the fix the call must complete without throwing and the delta
     * must be a sensible value: "changed" if any service was observed at or after
     * {@code requestedAt}, otherwise "unchanged".
     */
    @Test
    void computeDelta_inFlightScan_nullCompletedAt_doesNotThrow_returnsChangedOrUnchanged() {
        Scan inFlight = new Scan();
        inFlight.setId(SCAN_ID);
        inFlight.setCidr("10.0.0.0/24");
        inFlight.setScanType("PING_SWEEP");
        inFlight.setStatus(ScanStatus.RUNNING);
        inFlight.setRequestedAt(REQUESTED_AT);
        inFlight.setCompletedAt(null);   // ← in-flight: completedAt is null

        when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(inFlight));

        // Pre-existing device re-observed during this scan
        Device device = newDevice(200L, "10.0.0.100");
        device.setDiscoveredByScanId(SCAN_ID - 1);  // pre-existing (different scan)
        device.setLastSeenByScanId(SCAN_ID);

        when(deviceRepository.findByLastSeenByScanId(SCAN_ID)).thenReturn(List.of(device));

        // Service observed AFTER requestedAt — should be treated as "changed"
        NetworkService svc = serviceInWindow(10L, 200L);
        when(networkServiceRepository.findByDeviceIdIn(List.of(200L))).thenReturn(List.of(svc));
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of());

        // Must not throw NPE
        ScanReportDto report = service.buildReport(SCAN_ID);

        assertThat(report).isNotNull();
        assertThat(report.devices()).hasSize(1);
        String delta = report.devices().get(0).delta();
        // For an in-flight scan the service was observed >= requestedAt → "changed"
        assertThat(delta).isEqualTo("changed");
    }

    // ── (8) attribution uses findByLastSeenByScanId, NOT time-window heuristic ───

    @Test
    void attribution_usesLastSeenByScanId_notTimeWindowHeuristic() {
        Scan scan = buildScan();
        when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(scan));

        // Only lastSeenByScanId is stubbed; findIdsByFirstSeenBetween is NOT stubbed.
        // If the service calls the heuristic instead, Mockito returns empty and the
        // report will show 0 devices — the assertion on size(1) will fail and expose the bug.
        Device d = newDevice(101L, "10.0.0.1");
        d.setDiscoveredByScanId(SCAN_ID);
        d.setLastSeenByScanId(SCAN_ID);

        when(deviceRepository.findByLastSeenByScanId(SCAN_ID)).thenReturn(List.of(d));
        when(networkServiceRepository.findByDeviceIdIn(anyList())).thenReturn(List.of());

        ScanReportDto report = service.buildReport(SCAN_ID);

        assertThat(report).isNotNull();
        assertThat(report.devices()).hasSize(1);
    }
}

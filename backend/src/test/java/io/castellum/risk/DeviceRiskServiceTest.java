package io.castellum.risk;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DeviceRiskService#compute(Device, List)} — the package-private
 * scoring core. Calls the method directly (bypassing the {@code @Cacheable} proxy) to
 * verify the posture_severity contribution independently of CVE matching.
 *
 * <p>Tests cover:
 * <ol>
 *   <li>CRITICAL posture row with no CVE → score ≈ 9.0 (not 0).</li>
 *   <li>Null posture + no CVE → score == 0.00 (existing behaviour preserved).</li>
 *   <li>CVE composite beats a LOW posture row → headline is the CVE score.</li>
 *   <li>CRITICAL posture beats a low-score CVE → headline is the posture score.</li>
 * </ol>
 */
@ExtendWith(MockitoExtension.class)
class DeviceRiskServiceTest {

    @Mock DeviceRepository deviceRepo;
    @Mock NetworkServiceRepository networkServiceRepo;
    @Mock CveMatcher cveMatcher;
    @Mock EpssScoreRepository epssRepo;
    @Mock KevEntryRepository kevRepo;

    private DeviceRiskService service;

    private static final Device DEVICE;

    static {
        DEVICE = new Device(1L, "10.0.0.1", "host-1", null, Instant.now(), Instant.now(), Criticality.MEDIUM);
    }

    @BeforeEach
    void setUp() {
        service = new DeviceRiskService(deviceRepo, networkServiceRepo, cveMatcher, epssRepo, kevRepo);
        // Tests that need CVE matches stub cveMatcher individually — no blanket stub here
        // to avoid UnnecessaryStubbing failures in strict Mockito mode.
    }

    // ── Test 1: CRITICAL posture, no CVE → score ≈ 9.0 ──────────────────────

    @Test
    void compute_postureCritical_noCve_scoresCritical() {
        NetworkService svc = new NetworkService();
        svc.setDeviceId(1L);
        svc.setPort(2375);
        svc.setProtocol("tcp");
        svc.setPostureSeverity("CRITICAL");

        DeviceRiskService.DeviceRiskResult result = service.compute(DEVICE, List.of(svc));

        assertThat(result.dto().score())
            .as("CRITICAL posture with no CVE must score ~9.0 (not 0)")
            .isEqualByComparingTo(BigDecimal.valueOf(9.0).setScale(2));
    }

    // ── Test 2: null posture, no CVE → score 0.00 (existing behaviour) ───────

    @Test
    void compute_postureNull_noCve_scoresZero() {
        NetworkService svc = new NetworkService();
        svc.setDeviceId(1L);
        svc.setPort(80);
        svc.setProtocol("tcp");
        // postureSeverity is null by default

        DeviceRiskService.DeviceRiskResult result = service.compute(DEVICE, List.of(svc));

        assertThat(result.dto().score())
            .as("no posture, no CVE → score must be 0.00")
            .isEqualByComparingTo(BigDecimal.ZERO.setScale(2));
    }

    // ── Test 3: high-CVSS CVE beats LOW posture → headline = CVE composite ──

    @Test
    void compute_cveBeatsPosture() {
        // CVE: CVSS 9.8 (CRITICAL) — normalized to 0.98, composite >> LOW posture 3.0.
        Cve cve = new Cve();
        cve.setCveId("CVE-2024-00001");
        cve.setCvssV31Score(BigDecimal.valueOf(9.8));
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());

        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));
        when(epssRepo.findAllByCveIdIn(org.mockito.ArgumentMatchers.any())).thenReturn(List.of());
        when(kevRepo.findAllByCveIdIn(org.mockito.ArgumentMatchers.any())).thenReturn(List.of());

        NetworkService cveService = new NetworkService();
        cveService.setDeviceId(1L);
        cveService.setPort(443);
        cveService.setProtocol("tcp");
        cveService.setCpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*");
        // LOW posture — should NOT win over the CVE composite
        cveService.setPostureSeverity("LOW");

        DeviceRiskService.DeviceRiskResult result = service.compute(DEVICE, List.of(cveService));

        // CVE composite for CVSS 9.8 / MEDIUM criticality is well above LOW posture 3.0.
        assertThat(result.dto().score())
            .as("high CVE score must beat LOW posture — headline should be CVE composite")
            .isGreaterThan(BigDecimal.valueOf(3.0));
    }

    // ── Test 4: CRITICAL posture beats a low-CVSS CVE → posture wins ─────────

    @Test
    void compute_postureBeatsLowCve() {
        // CVE with CVSS 2.0 (LOW) — normalized to 0.2, composite will be << 9.0.
        Cve lowCve = new Cve();
        lowCve.setCveId("CVE-2024-00002");
        lowCve.setCvssV31Score(BigDecimal.valueOf(2.0));
        lowCve.setRawJson("{}");
        lowCve.setFetchedAt(Instant.now());
        lowCve.setLastModified(Instant.now());

        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(lowCve));
        when(epssRepo.findAllByCveIdIn(org.mockito.ArgumentMatchers.any())).thenReturn(List.of());
        when(kevRepo.findAllByCveIdIn(org.mockito.ArgumentMatchers.any())).thenReturn(List.of());

        NetworkService svc = new NetworkService();
        svc.setDeviceId(1L);
        svc.setPort(2375);
        svc.setProtocol("tcp");
        svc.setCpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*");
        svc.setPostureSeverity("CRITICAL"); // 9.0 — should beat the low CVE composite

        DeviceRiskService.DeviceRiskResult result = service.compute(DEVICE, List.of(svc));

        // CVE composite for CVSS 2.0 / MEDIUM criticality is well below 9.0.
        assertThat(result.dto().score())
            .as("CRITICAL posture must beat a low-CVSS CVE — headline should be posture score (9.0)")
            .isEqualByComparingTo(BigDecimal.valueOf(9.0).setScale(2));
    }
}

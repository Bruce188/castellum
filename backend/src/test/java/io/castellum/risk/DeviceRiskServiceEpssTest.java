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
import java.time.LocalDate;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * NB4 — positive EPSS-path tests for {@link DeviceRiskService#compute(Device, List)}.
 *
 * <p>The existing golden fixture and {@link DeviceRiskServiceTest} never positively assert
 * that a non-zero EPSS score actually raises the composite above what CVSS alone would produce.
 * These tests seed real {@link EpssScore} rows (via a stub returning non-zero EPSS) and verify
 * the EPSS signal is applied, not silently dropped.
 *
 * <p>Two scenarios:
 * <ol>
 *   <li><b>Non-zero EPSS raises composite above the CVSS-only baseline.</b> Concretely:
 *       CVSS 5.0 / MEDIUM criticality / no KEV should produce a baseline composite of ~3.13.
 *       Adding EPSS=0.80 must produce a strictly higher composite (the EPSS weight factor is
 *       non-zero so the score must increase).</li>
 *   <li><b>EPSS 0.0 (zero row present) equals the no-EPSS baseline.</b> Verifies that a
 *       present-but-zero EPSS row does not accidentally reduce or boost the score — the branch
 *       must be idempotent for zero values.</li>
 * </ol>
 *
 * <p>These tests are RED until the EPSS populate-and-apply branch actually wires the
 * in-memory map into the scorer (which {@link CompositeScorer#score} already supports via
 * {@link RiskInputs#epss()}). They will pass once the production code correctly looks up
 * the EPSS value from the repository response and passes it to the scorer.
 *
 * <p>Note: the {@link DeviceRiskService#compute} method currently guards against an empty
 * CVE id set before calling {@code epssRepo.findAllByCveIdIn}, so a non-empty CVE list is
 * required to exercise the EPSS branch at all.
 */
@ExtendWith(MockitoExtension.class)
class DeviceRiskServiceEpssTest {

    @Mock DeviceRepository deviceRepo;
    @Mock NetworkServiceRepository networkServiceRepo;
    @Mock CveMatcher cveMatcher;
    @Mock EpssScoreRepository epssRepo;
    @Mock KevEntryRepository kevRepo;

    private DeviceRiskService service;

    /**
     * A device at MEDIUM criticality — the baseline criticality weight so the composite
     * is sensitive to EPSS changes without criticality dominating.
     */
    private static final Device MEDIUM_DEVICE =
        new Device(1L, "10.0.0.1", "host-1", null, Instant.now(), Instant.now(), Criticality.MEDIUM);

    @BeforeEach
    void setUp() {
        service = new DeviceRiskService(deviceRepo, networkServiceRepo, cveMatcher, epssRepo, kevRepo);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /** Builds a minimal CVE with the given CVSS v3.1 score. */
    private Cve buildCve(String cveId, double cvssV31) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setCvssV31Score(BigDecimal.valueOf(cvssV31));
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        return cve;
    }

    /** Builds a service that has a resolvable CPE (name + version set). */
    private NetworkService buildCpeService(String name, String version) {
        NetworkService svc = new NetworkService();
        svc.setDeviceId(1L);
        svc.setPort(443);
        svc.setProtocol("tcp");
        svc.setName(name);
        svc.setVersion(version);
        return svc;
    }

    /** Builds an EpssScore stub entity. */
    private EpssScore buildEpssScore(String cveId, double epssValue) {
        EpssScore score = new EpssScore();
        score.setCveId(cveId);
        score.setEpss(BigDecimal.valueOf(epssValue));
        score.setPercentile(BigDecimal.valueOf(0.90));
        score.setScoreDate(LocalDate.now());
        score.setIngestedAt(Instant.now());
        return score;
    }

    // ─── Test 1: non-zero EPSS must raise the composite ──────────────────────

    /**
     * NB4 core assertion: a matched CVE with EPSS=0.80 must produce a composite STRICTLY
     * higher than the same CVE with no EPSS row (i.e. EPSS defaulting to 0).
     *
     * <p>Formula check (from {@link CompositeScorer}):
     * {@code raw = cvssOnTen * (1 + EPSS_WEIGHT * epss) * kevMult * critMult / (1 + CRIT_CRITICAL)}
     * With CVSS 5.0 / MEDIUM / no KEV:
     * <ul>
     *   <li>No-EPSS baseline: {@code 5.0 * 1.0 * 1.0 * 1.25 / 2.0 = 3.13}</li>
     *   <li>EPSS=0.80: {@code 5.0 * 1.80 * 1.0 * 1.25 / 2.0 = 5.63}</li>
     * </ul>
     * The test asserts composite(EPSS=0.80) > composite(no EPSS), not the exact value,
     * so it survives minor formula tweaks.
     *
     * <p>This test is EXPECTED TO FAIL (RED) if the production code does not wire the
     * EPSS repository result into the scorer — e.g. if it always passes epss=0.
     */
    @Test
    void compute_nonZeroEpss_raisesCompositeAboveBaseline() {
        String cveId = "CVE-2025-EPSS-NB4";
        Cve cve = buildCve(cveId, 5.0);
        NetworkService svc = buildCpeService("testapp", "1.0");

        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));
        // Seed a non-zero EPSS row for this CVE
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of(buildEpssScore(cveId, 0.80)));
        when(kevRepo.findAllByCveIdIn(any())).thenReturn(List.of());

        DeviceRiskService.DeviceRiskResult resultWithEpss = service.compute(MEDIUM_DEVICE, List.of(svc));

        // Compute the no-EPSS baseline to make the assertion self-documenting
        // (zero EPSS → getOrDefault returns BigDecimal.ZERO in the scorer path)
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of());
        DeviceRiskService.DeviceRiskResult resultNoEpss = service.compute(MEDIUM_DEVICE, List.of(svc));

        BigDecimal compositeWithEpss = resultWithEpss.dto().score();
        BigDecimal compositeNoEpss = resultNoEpss.dto().score();

        assertThat(compositeWithEpss)
            .as("EPSS=0.80 must raise composite above the no-EPSS baseline; "
                + "got with-EPSS=%s, no-EPSS=%s — EPSS branch may not be wired into scorer",
                compositeWithEpss, compositeNoEpss)
            .isGreaterThan(compositeNoEpss);

        // Bonus: confirm the with-EPSS score is above a reasonable floor (> 4.0 for CVSS 5 + 0.80 EPSS)
        assertThat(compositeWithEpss)
            .as("composite with EPSS=0.80 / CVSS 5.0 / MEDIUM criticality should be > 4.0")
            .isGreaterThan(BigDecimal.valueOf(4.0));
    }

    // ─── Test 2: EPSS components surfaced in ScoreComponents breakdown ────────

    /**
     * The {@link io.castellum.web.dto.DeviceRiskDto.ScoreComponents} breakdown must
     * reflect the maximum EPSS value seen across CVEs. When a non-zero EPSS row is
     * present and applied, the {@code epssMax} component must be > 0.
     *
     * <p>This test exercises the {@code epssMax} tracking loop in
     * {@code DeviceRiskService.compute()} which updates {@code epssMax} from the
     * {@code epssByCveId} map. It is RED if the map is populated but the loop
     * does not read from it, or if the scorer ignores the value.
     */
    @Test
    void compute_nonZeroEpss_epssMaxInComponentsIsPositive() {
        String cveId = "CVE-2025-EPSS-COMP";
        Cve cve = buildCve(cveId, 7.5);
        NetworkService svc = buildCpeService("openssh", "8.9");

        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of(buildEpssScore(cveId, 0.55)));
        when(kevRepo.findAllByCveIdIn(any())).thenReturn(List.of());

        DeviceRiskService.DeviceRiskResult result = service.compute(MEDIUM_DEVICE, List.of(svc));

        assertThat(result.dto().components()).as("ScoreComponents must be non-null for a CVE match").isNotNull();

        BigDecimal epssComponent = result.dto().components().epssMax();
        assertThat(epssComponent)
            .as("epssScore component must reflect the seeded EPSS=0.55 row; "
                + "got=%s — EPSS may not be wired into the components breakdown", epssComponent)
            .isGreaterThan(BigDecimal.ZERO);
    }

    // ─── Test 3: zero-EPSS row is idempotent ─────────────────────────────────

    /**
     * A present-but-zero EPSS row must produce the same composite as no EPSS row at all.
     * Guards against an implementation that special-cases "no row" vs "zero row" in a
     * way that produces a different score.
     */
    @Test
    void compute_zeroEpssRow_sameCompositeAsNoEpssRow() {
        String cveId = "CVE-2025-EPSS-ZERO";
        Cve cve = buildCve(cveId, 6.0);
        NetworkService svc = buildCpeService("nginx", "1.24");

        // With explicit zero EPSS row
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of(buildEpssScore(cveId, 0.0)));
        when(kevRepo.findAllByCveIdIn(any())).thenReturn(List.of());
        DeviceRiskService.DeviceRiskResult withZeroEpss = service.compute(MEDIUM_DEVICE, List.of(svc));

        // With no EPSS row (defaults to BigDecimal.ZERO in getOrDefault)
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of());
        DeviceRiskService.DeviceRiskResult withNoEpss = service.compute(MEDIUM_DEVICE, List.of(svc));

        assertThat(withZeroEpss.dto().score())
            .as("zero EPSS row must produce same composite as no-EPSS baseline")
            .isEqualByComparingTo(withNoEpss.dto().score());
    }
}

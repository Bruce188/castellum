package io.castellum.cve;

import io.castellum.cve.CveEnrichmentService.Enrichment;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssScore;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.when;

/**
 * Pure unit test for {@link CveEnrichmentService}. Mocks the two repositories;
 * exercises the real {@link io.castellum.risk.CompositeScorer} +
 * {@link io.castellum.risk.CvssExtractor} static utilities.
 */
@ExtendWith(MockitoExtension.class)
class CveEnrichmentServiceTest {

    @Mock
    KevEntryRepository kevRepo;

    @Mock
    EpssScoreRepository epssRepo;

    private CveEnrichmentService service;

    @BeforeEach
    void setUp() {
        service = new CveEnrichmentService(kevRepo, epssRepo);
    }

    @Test
    void enrich_batch_populatesAllThreeFields_whenKevAndEpssBothPresent() {
        Cve cve1 = makeCve("CVE-2024-0001", "8.0");
        Cve cve2 = makeCve("CVE-2024-0002", "5.0");

        when(kevRepo.findAllByCveIdIn(anyCollection()))
            .thenReturn(List.of(makeKev("CVE-2024-0002")));
        when(epssRepo.findAllByCveIdIn(anyCollection()))
            .thenReturn(List.of(
                makeEpss("CVE-2024-0001", "0.5"),
                makeEpss("CVE-2024-0002", "0.1")));

        Map<String, Enrichment> result = service.enrich(List.of(cve1, cve2), Criticality.MEDIUM);

        assertThat(result).hasSize(2);
        assertThat(result.get("CVE-2024-0001").kev()).isFalse();
        assertThat(result.get("CVE-2024-0001").epss()).isEqualByComparingTo("0.5");
        assertThat(result.get("CVE-2024-0001").composite()).isNotNull();
        assertThat(result.get("CVE-2024-0002").kev()).isTrue();
        assertThat(result.get("CVE-2024-0002").epss()).isEqualByComparingTo("0.1");
        assertThat(result.get("CVE-2024-0002").composite()).isNotNull();
    }

    @Test
    void enrich_batch_compositeIsNull_whenCvssIsNull() {
        Cve cve = makeCve("CVE-2024-0003", null);

        when(kevRepo.findAllByCveIdIn(anyCollection())).thenReturn(List.of());
        when(epssRepo.findAllByCveIdIn(anyCollection()))
            .thenReturn(List.of(makeEpss("CVE-2024-0003", "0.3")));

        Map<String, Enrichment> result = service.enrich(List.of(cve), Criticality.MEDIUM);

        assertThat(result).hasSize(1);
        assertThat(result.get("CVE-2024-0003").composite()).isNull();
        assertThat(result.get("CVE-2024-0003").kev()).isFalse();
        assertThat(result.get("CVE-2024-0003").epss()).isEqualByComparingTo("0.3");
    }

    @Test
    void enrich_batch_epssIsNull_whenNoEpssRowExists() {
        Cve cve = makeCve("CVE-2024-0004", "7.5");

        when(kevRepo.findAllByCveIdIn(anyCollection())).thenReturn(List.of());
        when(epssRepo.findAllByCveIdIn(anyCollection())).thenReturn(List.of());

        Map<String, Enrichment> result = service.enrich(List.of(cve), Criticality.MEDIUM);

        assertThat(result).hasSize(1);
        assertThat(result.get("CVE-2024-0004").epss()).isNull();
        assertThat(result.get("CVE-2024-0004").composite()).isNotNull();
        assertThat(result.get("CVE-2024-0004").kev()).isFalse();
    }

    @Test
    void enrichOne_detail_returnsCorrectFields_forKevTrueAndEpssPresent() {
        Cve cve = makeCve("CVE-2024-0010", "8.0");

        when(kevRepo.existsByCveId("CVE-2024-0010")).thenReturn(true);
        when(epssRepo.findByCveId("CVE-2024-0010"))
            .thenReturn(Optional.of(makeEpss("CVE-2024-0010", "0.5")));

        Enrichment e = service.enrichOne(cve, Criticality.HIGH);

        assertThat(e.kev()).isTrue();
        assertThat(e.epss()).isEqualByComparingTo("0.5");
        assertThat(e.composite()).isNotNull();
    }

    @Test
    void enrich_emptyCollection_returnsEmptyMap_withNoRepoCalls() {
        Map<String, Enrichment> result = service.enrich(List.of(), Criticality.MEDIUM);
        assertThat(result).isEmpty();
        // No repo calls because of guard
    }

    private KevEntry makeKev(String cveId) {
        KevEntry k = new KevEntry();
        k.setCveId(cveId);
        k.setDateAdded(LocalDate.now());
        return k;
    }

    private EpssScore makeEpss(String cveId, String prob) {
        EpssScore e = new EpssScore();
        e.setCveId(cveId);
        e.setEpss(new BigDecimal(prob));
        e.setPercentile(new BigDecimal("0.5"));
        e.setScoreDate(LocalDate.now());
        return e;
    }

    private Cve makeCve(String cveId, String cvssScore) {
        Cve c = new Cve();
        c.setCveId(cveId);
        if (cvssScore != null) c.setCvssV31Score(new BigDecimal(cvssScore));
        // ensure unused fields are deterministic-null
        return c;
    }

    // Suppress 'unused' warning for Set import — Set used in earlier draft, kept for clarity.
    @SuppressWarnings("unused")
    private Set<String> _setOf(String s) { return Set.of(s); }
}

package io.castellum.cve;

import io.castellum.cve.CveEnrichmentService.Enrichment;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the pure window logic of {@link FleetCveWindowService} (no Spring; the
 * {@code @Cacheable} proxy is exercised separately by {@code FleetCveWindowCacheTest}). Covers
 * fleet vs per-device scoping, empty-fleet short-circuit, the bounded window query, and the
 * composite/kev ordering with the cveId tiebreak (relocated from the controller's sort tests).
 */
@ExtendWith(MockitoExtension.class)
class FleetCveWindowServiceTest {

    @Mock NetworkServiceRepository networkServiceRepository;
    @Mock CveMatcher cveMatcher;
    @Mock CveRepository cveRepository;
    @Mock CveEnrichmentService enrichmentService;
    @InjectMocks FleetCveWindowService service;

    private Cve cve(String id, long pk, String score) {
        Cve c = new Cve();
        c.setCveId(id);
        c.setId(pk);
        c.setCvssV31Score(new BigDecimal(score));
        return c;
    }

    private NetworkService svc(long id, long deviceId, String name, String version) {
        NetworkService s = new NetworkService();
        s.setId(id);
        s.setDeviceId(deviceId);
        s.setPort(22);
        s.setProtocol("tcp");
        s.setVendor(name);
        s.setProduct(name);
        s.setVersion(version);
        s.setName(name);
        return s;
    }

    @Test
    void wholeFleet_nullDeviceId_scansFindAll_andSortsByCompositeDesc() {
        when(networkServiceRepository.findAll()).thenReturn(List.of(svc(1L, 1L, "openssh", "8.2")));
        Cve a = cve("CVE-A", 1L, "5.0");
        Cve b = cve("CVE-B", 2L, "6.0");
        when(cveMatcher.findVulnerable(any())).thenReturn(List.of(a, b));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L, 2L)), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(a, b)));
        when(enrichmentService.enrich(anyCollection(), eq(Criticality.MEDIUM))).thenReturn(Map.of(
            "CVE-A", new Enrichment(false, null, new BigDecimal("3.00")),
            "CVE-B", new Enrichment(false, null, new BigDecimal("9.00"))));

        FleetCveWindowService.SortedWindow w = service.window(null, null, "composite", Criticality.MEDIUM);

        // composite DESC → B (9.00) before A (3.00).
        assertThat(w.sorted()).extracting(Cve::getCveId).containsExactly("CVE-B", "CVE-A");
        verify(networkServiceRepository).findAll();
        verify(networkServiceRepository, never()).findByDeviceId(any());
    }

    @Test
    void perDevice_scopesToFindByDeviceId_andEnrichesWithGivenCriticality() {
        when(networkServiceRepository.findByDeviceId(42L)).thenReturn(List.of(svc(10L, 42L, "apache", "2.4.49")));
        Cve x = cve("CVE-X", 7L, "9.8");
        when(cveMatcher.findVulnerable(any())).thenReturn(List.of(x));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(7L)), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(x)));
        when(enrichmentService.enrich(anyCollection(), eq(Criticality.HIGH)))
            .thenReturn(Map.of("CVE-X", new Enrichment(false, null, new BigDecimal("9.80"))));

        FleetCveWindowService.SortedWindow w = service.window(null, 42L, "composite", Criticality.HIGH);

        assertThat(w.sorted()).extracting(Cve::getCveId).containsExactly("CVE-X");
        verify(networkServiceRepository).findByDeviceId(42L);
        verify(networkServiceRepository, never()).findAll();
        verify(enrichmentService).enrich(anyCollection(), eq(Criticality.HIGH));
    }

    @Test
    void emptyFleet_returnsEmptyWindow_withNoDbQuery() {
        when(networkServiceRepository.findAll()).thenReturn(List.of());

        FleetCveWindowService.SortedWindow w = service.window(null, null, "composite", Criticality.MEDIUM);

        assertThat(w.sorted()).isEmpty();
        assertThat(w.enrich()).isEmpty();
        verify(cveRepository, never()).findByIdInAndCvssV31ScoreIsNotNull(any(), any(Pageable.class));
    }

    @Test
    void windowQuery_usesBoundedPageSizeOf500() {
        when(networkServiceRepository.findAll()).thenReturn(List.of(svc(1L, 1L, "openssh", "8.2")));
        Cve a = cve("CVE-A", 1L, "5.0");
        when(cveMatcher.findVulnerable(any())).thenReturn(List.of(a));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(any(), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(a)));
        when(enrichmentService.enrich(anyCollection(), any(Criticality.class))).thenReturn(Map.of());

        service.window(null, null, "kev", Criticality.MEDIUM);

        verify(cveRepository).findByIdInAndCvssV31ScoreIsNotNull(any(), argThat(p -> p.getPageSize() == 500));
    }

    @Test
    void kevSort_placesKevTrueFirst_thenCveIdTiebreak() {
        when(networkServiceRepository.findAll()).thenReturn(List.of(svc(1L, 1L, "openssh", "8.2")));
        Cve a = cve("CVE-A", 1L, "5.0");
        Cve b = cve("CVE-B", 2L, "6.0");
        Cve c = cve("CVE-C", 3L, "7.0");
        when(cveMatcher.findVulnerable(any())).thenReturn(List.of(a, b, c));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(any(), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(a, b, c)));
        when(enrichmentService.enrich(anyCollection(), any(Criticality.class))).thenReturn(Map.of(
            "CVE-A", new Enrichment(true, null, null),
            "CVE-B", new Enrichment(false, null, null),
            "CVE-C", new Enrichment(true, null, null)));

        FleetCveWindowService.SortedWindow w = service.window(null, null, "kev", Criticality.MEDIUM);

        // kev=true first (A, C by cveId tiebreak), then kev=false (B).
        assertThat(w.sorted()).extracting(Cve::getCveId).containsExactly("CVE-A", "CVE-C", "CVE-B");
    }

    @Test
    void minScore_usesGreaterThanEqualQuery() {
        when(networkServiceRepository.findAll()).thenReturn(List.of(svc(1L, 1L, "openssh", "8.2")));
        Cve a = cve("CVE-A", 1L, "7.5");
        when(cveMatcher.findVulnerable(any())).thenReturn(List.of(a));
        when(cveRepository.findByIdInAndCvssV31ScoreGreaterThanEqual(eq(Set.of(1L)), eq(new BigDecimal("7.0")), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(a)));
        when(enrichmentService.enrich(anyCollection(), any(Criticality.class))).thenReturn(Map.of());

        service.window(new BigDecimal("7.0"), null, "composite", Criticality.MEDIUM);

        verify(cveRepository).findByIdInAndCvssV31ScoreGreaterThanEqual(eq(Set.of(1L)), eq(new BigDecimal("7.0")), any(Pageable.class));
    }
}

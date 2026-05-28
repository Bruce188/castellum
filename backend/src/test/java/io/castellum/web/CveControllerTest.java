package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.cve.Cve;
import io.castellum.cve.CveEnrichmentService;
import io.castellum.cve.CveEnrichmentService.Enrichment;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.KevEntryRepository;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyIterable;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(CveController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class CveControllerTest {

    @Autowired
    MockMvc mockMvc;
    @MockBean
    AuditService auditService;

    @MockBean
    CveRepository cveRepository;

    @MockBean
    CveMatcher cveMatcher;

    @MockBean
    NetworkServiceRepository networkServiceRepository;

    @MockBean
    CveEnrichmentService enrichment;

    @MockBean
    KevEntryRepository kevEntryRepository;

    @MockBean
    DeviceRepository deviceRepository;

    @MockBean
    CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean
    UserRepository userRepository;

    /** Default enrichment stub: empty payload (kev=false, epss=null, composite=null per entry). */
    private void stubEnrichmentEmpty() {
        when(enrichment.enrich(anyCollection(), any(Criticality.class)))
            .thenReturn(Map.of());
        when(enrichment.enrichOne(any(Cve.class), any(Criticality.class)))
            .thenReturn(new Enrichment(Boolean.FALSE, null, null));
    }

    private Cve buildCve(String cveId) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setLastModified(Instant.parse("2023-11-07T03:18:00.640Z"));
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        return cve;
    }

    @Test
    void getByCveId_existingRecord_returns200WithBody() throws Exception {
        Cve cve = buildCve("CVE-2020-15778");
        when(cveRepository.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(cve));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/CVE-2020-15778")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.cveId").value("CVE-2020-15778"));
    }

    @Test
    void getByCveId_missingRecord_returns404() throws Exception {
        when(cveRepository.findByCveId("CVE-9999-9999")).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/cve/CVE-9999-9999")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isNotFound());
    }

    @Test
    void findByCpe_invokesMatcher_andReturnsJson() throws Exception {
        String cpe = "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*";
        Cve cve = buildCve("CVE-2020-15778");
        when(cveMatcher.findVulnerable(cpe)).thenReturn(List.of(cve));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve")
                .param("cpe", cpe)
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].cveId").value("CVE-2020-15778"));

        verify(cveMatcher).findVulnerable(eq(cpe));
    }

    @Test
    void anon_returns401() throws Exception {
        mockMvc.perform(get("/api/cve/CVE-2020-15778").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_canRead_returns200() throws Exception {
        Cve cve = buildCve("CVE-2020-15778");
        when(cveRepository.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(cve));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/CVE-2020-15778")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void findByCpe_responseDoesNotExposeRawJson() throws Exception {
        Cve cve = buildCve("CVE-2020-15778");
        cve.setRawJson("{\"sentinel\":true}");
        when(cveMatcher.findVulnerable(any())).thenReturn(List.of(cve));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve")
                .param("cpe", "cpe:2.3:a:test:test:1.0")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].cveId").exists())
            .andExpect(jsonPath("$[0].rawJson").doesNotExist());
    }

    /** Shared helper — sets up a single fleet service with a canonical name so the
     *  no-device scoped-union path resolves through {@code findByIdIn…} queries. */
    private void stubFleetService(NetworkService svc, String canonicalCpe, List<Cve> matched) {
        when(networkServiceRepository.findAll()).thenReturn(List.of(svc));
        when(cveMatcher.findVulnerable(canonicalCpe)).thenReturn(matched);
    }

    @Test
    void fleet_default_returnsPageOrderedByScore() throws Exception {
        Cve critical = buildCve("CVE-2024-0001");
        critical.setId(1L);
        critical.setCvssV31Score(new BigDecimal("9.8"));
        Cve high = buildCve("CVE-2024-0002");
        high.setId(2L);
        high.setCvssV31Score(new BigDecimal("7.5"));

        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(critical, high));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L, 2L)), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(critical, high)));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-2024-0001"))
            .andExpect(jsonPath("$.content[1].cveId").value("CVE-2024-0002"))
            .andExpect(jsonPath("$.content[0].rawJson").doesNotExist());

        verify(cveRepository).findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L, 2L)), any(Pageable.class));
    }

    @Test
    void fleet_minScore_filtersBelowFloor() throws Exception {
        Cve high = buildCve("CVE-2024-0010");
        high.setId(10L);
        high.setCvssV31Score(new BigDecimal("7.5"));

        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(high));
        when(cveRepository.findByIdInAndCvssV31ScoreGreaterThanEqual(eq(Set.of(10L)), eq(new BigDecimal("7.0")), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(high)));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet")
                .param("minScore", "7.0")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-2024-0010"));

        verify(cveRepository).findByIdInAndCvssV31ScoreGreaterThanEqual(eq(Set.of(10L)), eq(new BigDecimal("7.0")), any(Pageable.class));
    }

    @Test
    void fleet_size_clampedTo100() throws Exception {
        Cve cve = buildCve("CVE-2024-CLAMP");
        cve.setId(99L);
        cve.setCvssV31Score(new BigDecimal("7.0"));

        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(cve));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(any(), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of()));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").param("size", "500"))
            .andExpect(status().isOk());

        org.mockito.ArgumentCaptor<Pageable> captor = org.mockito.ArgumentCaptor.forClass(Pageable.class);
        verify(cveRepository).findByIdInAndCvssV31ScoreIsNotNull(any(), captor.capture());
        org.junit.jupiter.api.Assertions.assertEquals(100, captor.getValue().getPageSize());
    }

    @Test
    void fleet_anon_returns401() throws Exception {
        mockMvc.perform(get("/api/cve/fleet").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void fleet_viewer_canRead() throws Exception {
        when(networkServiceRepository.findAll()).thenReturn(List.of());
        stubEnrichmentEmpty();
        mockMvc.perform(get("/api/cve/fleet"))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void getByCveId_responseExposesRawJson() throws Exception {
        Cve cve = buildCve("CVE-2020-15778");
        cve.setRawJson("{\"sentinel\":true}");
        when(cveRepository.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(cve));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/CVE-2020-15778")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.cveId").value("CVE-2020-15778"))
            .andExpect(jsonPath("$.rawJson").value(containsString("sentinel")));
    }

    private NetworkService buildService(Long id, Long deviceId, String vendor, String product, String version) {
        NetworkService s = new NetworkService();
        s.setId(id);
        s.setDeviceId(deviceId);
        s.setPort(22);
        s.setProtocol("tcp");
        s.setVendor(vendor);
        s.setProduct(product);
        s.setVersion(version);
        return s;
    }

    @Test
    void fleet_deviceId_filtersByDeviceServices_returnsFilteredPage() throws Exception {
        NetworkService ssh = buildService(1L, 42L, "openssh", "openssh", "8.2");
        ssh.setName("openssh");
        NetworkService httpd = buildService(2L, 42L, "apache", "httpd", "2.4.49");
        httpd.setName("apache");
        when(networkServiceRepository.findByDeviceId(42L)).thenReturn(List.of(ssh, httpd));

        Cve cve1 = buildCve("CVE-2020-15778");
        cve1.setId(1L);
        cve1.setCvssV31Score(new BigDecimal("7.8"));
        Cve cve2 = buildCve("CVE-2021-41773");
        cve2.setId(2L);
        cve2.setCvssV31Score(new BigDecimal("9.8"));

        when(cveMatcher.findVulnerable("cpe:2.3:a:openssh:openssh:8.2:*:*:*:*:*:*:*")).thenReturn(List.of(cve1));
        when(cveMatcher.findVulnerable("cpe:2.3:a:apache:apache:2.4.49:*:*:*:*:*:*:*")).thenReturn(List.of(cve2));

        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L, 2L)), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(cve2, cve1)));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").param("deviceId", "42")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content.length()").value(2))
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-2021-41773"))
            .andExpect(jsonPath("$.content[1].cveId").value("CVE-2020-15778"));

        verify(cveMatcher).findVulnerable("cpe:2.3:a:openssh:openssh:8.2:*:*:*:*:*:*:*");
        verify(cveMatcher).findVulnerable("cpe:2.3:a:apache:apache:2.4.49:*:*:*:*:*:*:*");
        verify(cveRepository).findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L, 2L)), any(Pageable.class));
    }

    @Test
    void fleet_deviceIdAbsent_returnsFleetScopedUnion() throws Exception {
        // AC2 — the no-deviceId path returns CVEs scoped to the union of matched
        // fleet services, NOT the entire v3.1-scored corpus.
        NetworkService svc = buildService(10L, 1L, "openssh", "openssh", "8.2");
        svc.setName("openssh");
        when(networkServiceRepository.findAll()).thenReturn(List.of(svc));

        Cve cve = buildCve("CVE-2024-0099");
        cve.setId(99L);
        cve.setCvssV31Score(new BigDecimal("8.1"));
        when(cveMatcher.findVulnerable("cpe:2.3:a:openssh:openssh:8.2:*:*:*:*:*:*:*"))
            .thenReturn(List.of(cve));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(99L)), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(cve)));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-2024-0099"));

        verify(cveRepository).findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(99L)), any(Pageable.class));
        // The full-corpus query must never be called for the no-device fleet path.
        org.mockito.Mockito.verify(cveRepository, org.mockito.Mockito.never())
            .findByCvssV31ScoreIsNotNull(any(Pageable.class));
    }

    @Test
    void fleet_deviceIdAbsent_emptyFleet_returnsEmptyPage() throws Exception {
        // AC2 — empty service list → empty scoped page, never the corpus.
        when(networkServiceRepository.findAll()).thenReturn(List.of());
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content.length()").value(0))
            .andExpect(jsonPath("$.totalElements").value(0));

        org.mockito.Mockito.verify(cveRepository, org.mockito.Mockito.never())
            .findByCvssV31ScoreIsNotNull(any(Pageable.class));
    }

    @Test
    void fleet_deviceIdUnknown_returns200WithEmptyPage() throws Exception {
        when(networkServiceRepository.findByDeviceId(99999L)).thenReturn(List.of());
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").param("deviceId", "99999")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content.length()").value(0))
            .andExpect(jsonPath("$.totalElements").value(0));
    }

    // ─────────────────────────────────────────────────────────────────────
    // v3-F1 — kev/epss/composite surfacing, kevOnly filter, sort dispatch
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Test 1 — every fleet row carries the three enrichment fields when populated.
     * Asserts response payload exposes {@code kev}, {@code epssScore},
     * {@code compositeScore} JSON paths populated from the mocked
     * {@link CveEnrichmentService} batch result.
     */
    @Test
    void fleetResponseContainsKevEpssCompositeFields() throws Exception {
        Cve cve = buildCve("CVE-2024-0001");
        cve.setId(1L);
        cve.setCvssV31Score(new BigDecimal("8.0"));

        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(cve));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L)), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(cve)));
        when(enrichment.enrich(anyCollection(), eq(Criticality.MEDIUM)))
            .thenReturn(Map.of("CVE-2024-0001",
                new Enrichment(Boolean.TRUE, new BigDecimal("0.5"), new BigDecimal("8.50"))));

        mockMvc.perform(get("/api/cve/fleet").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].kev").value(true))
            .andExpect(jsonPath("$.content[0].epssScore").value(0.5))
            .andExpect(jsonPath("$.content[0].compositeScore").value(8.50));
    }

    /**
     * Test 2 — {@code ?kevOnly=true} narrows the result set to CVEs that are BOTH in the
     * CISA KEV catalog AND matched to a fleet service. A KEV CVE that no fleet service
     * matches must be excluded; the controller intersects the fleet-matched FK set with
     * the KEV catalog via {@code findByIdInAndCveIdInAndCvssV31ScoreIsNotNull}.
     */
    @Test
    void fleetKevOnlyFilterNarrowsToFleetMatchedKevCves() throws Exception {
        // KEV catalog has three entries; only CVE-A and CVE-B are matched on the network.
        // CVE-OFFNET is in the catalog but matches no fleet service → must be excluded.
        when(kevEntryRepository.findAllCveIds()).thenReturn(List.of("CVE-A", "CVE-B", "CVE-OFFNET"));

        Cve cveA = buildCve("CVE-A");
        cveA.setId(1L);
        cveA.setCvssV31Score(new BigDecimal("9.0"));
        Cve cveB = buildCve("CVE-B");
        cveB.setId(2L);
        cveB.setCvssV31Score(new BigDecimal("8.0"));

        // Fleet has a single service matching CVE-A and CVE-B (FKs 1, 2). CVE-OFFNET (no FK)
        // is in the catalog but is not part of the fleet-matched set.
        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(cveA, cveB));

        // Intersection query: FKs {1,2} ∩ KEV catalog → the two on-network KEV CVEs only.
        when(cveRepository.findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(
                eq(Set.of(1L, 2L)), eq(Set.of("CVE-A", "CVE-B", "CVE-OFFNET")), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(cveA, cveB)));

        Map<String, Enrichment> enrichMap = new HashMap<>();
        enrichMap.put("CVE-A", new Enrichment(Boolean.TRUE, new BigDecimal("0.40"), new BigDecimal("9.00")));
        enrichMap.put("CVE-B", new Enrichment(Boolean.TRUE, new BigDecimal("0.30"), new BigDecimal("8.00")));
        when(enrichment.enrich(anyCollection(), any(Criticality.class))).thenReturn(enrichMap);

        mockMvc.perform(get("/api/cve/fleet").param("kevOnly", "true")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content", hasSize(2)))
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-A"))
            .andExpect(jsonPath("$.content[1].cveId").value("CVE-B"))
            .andExpect(jsonPath("$.content[0].kev").value(true))
            .andExpect(jsonPath("$.content[1].kev").value(true));

        // The intersection query is dispatched with the fleet FKs AND the KEV catalog.
        verify(cveRepository).findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(
                eq(Set.of(1L, 2L)), eq(Set.of("CVE-A", "CVE-B", "CVE-OFFNET")), any(Pageable.class));
        // The old unscoped catalog-only query must never run for the kevOnly path.
        org.mockito.Mockito.verify(cveRepository, org.mockito.Mockito.never())
            .findByCveIdInAndCvssV31ScoreIsNotNull(any(), any(Pageable.class));
    }

    /**
     * Regression — reproduces the original bug where {@code kevOnly=true} returned the
     * ENTIRE KEV catalog (e.g. ~1599 rows) even though the fleet matched far fewer CVEs.
     * With the intersection fix the result set is a subset of the fleet-matched set, so
     * its size can never exceed the number of fleet-matched CVEs.
     */
    @Test
    void fleetKevOnly_resultNeverExceedsFleetMatchedCount() throws Exception {
        // A large KEV catalog (stand-in for the live ~1599-entry catalog).
        List<String> hugeCatalog = new java.util.ArrayList<>();
        for (int i = 0; i < 1599; i++) {
            hugeCatalog.add(String.format("CVE-9999-%04d", i));
        }
        when(kevEntryRepository.findAllCveIds()).thenReturn(hugeCatalog);

        // The fleet matches exactly ONE CVE, and that CVE happens to be in the catalog.
        Cve onNet = buildCve("CVE-9999-0000");
        onNet.setId(1L);
        onNet.setCvssV31Score(new BigDecimal("7.5"));
        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(onNet));

        // The intersection query is constrained by the single fleet FK, so the DB returns
        // at most the fleet-matched rows — never the whole catalog.
        when(cveRepository.findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(
                eq(Set.of(1L)), anyCollection(), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(onNet)));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").param("kevOnly", "true")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            // Result size (1) is ≤ fleet-matched count (1), not the 1599-row catalog.
            .andExpect(jsonPath("$.content", hasSize(1)))
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-9999-0000"));

        verify(cveRepository).findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(
                eq(Set.of(1L)), anyCollection(), any(Pageable.class));
    }

    /**
     * kevOnly with an empty fleet (no matched services) returns an empty page — never the
     * catalog. Guards the short-circuit when {@code fleetMatchedFks} is empty.
     */
    @Test
    void fleetKevOnly_emptyFleet_returnsEmptyPage() throws Exception {
        when(kevEntryRepository.findAllCveIds()).thenReturn(List.of("CVE-A", "CVE-B"));
        when(networkServiceRepository.findAll()).thenReturn(List.of());
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").param("kevOnly", "true")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content.length()").value(0))
            .andExpect(jsonPath("$.totalElements").value(0));

        // No CVE query of any kind should run when the fleet matches nothing.
        org.mockito.Mockito.verify(cveRepository, org.mockito.Mockito.never())
            .findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(any(), any(), any(Pageable.class));
        org.mockito.Mockito.verify(cveRepository, org.mockito.Mockito.never())
            .findByCveIdInAndCvssV31ScoreIsNotNull(any(), any(Pageable.class));
    }

    /**
     * Test 3 — {@code ?sort=composite} orders rows by composite score DESC,
     * exercising the enrichment-window path (fetch wider candidate set, enrich,
     * sort in-memory, slice). The window path now also goes through the scoped
     * union for the no-deviceId case.
     */
    @Test
    void fleetSortByCompositeReturnsHighestCompositeFirst() throws Exception {
        Cve cveA = buildCve("CVE-A");
        cveA.setId(1L);
        cveA.setCvssV31Score(new BigDecimal("5.0"));
        Cve cveB = buildCve("CVE-B");
        cveB.setId(2L);
        cveB.setCvssV31Score(new BigDecimal("6.0"));
        Cve cveC = buildCve("CVE-C");
        cveC.setId(3L);
        cveC.setCvssV31Score(new BigDecimal("7.0"));

        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(cveA, cveB, cveC));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L, 2L, 3L)), argThat(p -> p.getPageSize() > 20)))
            .thenReturn(new PageImpl<>(List.of(cveA, cveB, cveC)));

        Map<String, Enrichment> enrichMap = new HashMap<>();
        enrichMap.put("CVE-A", new Enrichment(Boolean.FALSE, null, new BigDecimal("3.10")));
        enrichMap.put("CVE-B", new Enrichment(Boolean.FALSE, null, new BigDecimal("9.20")));
        enrichMap.put("CVE-C", new Enrichment(Boolean.FALSE, null, new BigDecimal("7.40")));
        when(enrichment.enrich(anyCollection(), any(Criticality.class))).thenReturn(enrichMap);

        mockMvc.perform(get("/api/cve/fleet").param("sort", "composite")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-B"))
            .andExpect(jsonPath("$.content[1].cveId").value("CVE-C"))
            .andExpect(jsonPath("$.content[2].cveId").value("CVE-A"));

        // The enrichment-window path MUST request a wider candidate set than the page size.
        // With the scoped union the wider window is now via findByIdIn... with expanded pageable.
        verify(cveRepository).findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L, 2L, 3L)), argThat(p -> p.getPageSize() > 20));
    }

    /**
     * Test 4 — {@code ?sort=kev} places KEV-true rows before KEV-false rows.
     * Tiebreak on {@code cveId} ASC ensures determinism per
     * {@code comparatorFor}'s {@code thenComparing(Cve::getCveId)} clause.
     */
    @Test
    void fleetSortByKevPlacesKevTrueRowsFirst() throws Exception {
        Cve cveA = buildCve("CVE-A");
        cveA.setId(1L);
        cveA.setCvssV31Score(new BigDecimal("5.0"));
        Cve cveB = buildCve("CVE-B");
        cveB.setId(2L);
        cveB.setCvssV31Score(new BigDecimal("6.0"));
        Cve cveC = buildCve("CVE-C");
        cveC.setId(3L);
        cveC.setCvssV31Score(new BigDecimal("7.0"));

        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(cveA, cveB, cveC));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L, 2L, 3L)), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(cveA, cveB, cveC)));

        Map<String, Enrichment> enrichMap = new HashMap<>();
        enrichMap.put("CVE-A", new Enrichment(Boolean.TRUE, null, new BigDecimal("3.00")));
        enrichMap.put("CVE-B", new Enrichment(Boolean.FALSE, null, new BigDecimal("6.00")));
        enrichMap.put("CVE-C", new Enrichment(Boolean.TRUE, null, new BigDecimal("7.00")));
        when(enrichment.enrich(anyCollection(), any(Criticality.class))).thenReturn(enrichMap);

        mockMvc.perform(get("/api/cve/fleet").param("sort", "kev")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            // First two are kev=true (CVE-A, CVE-C — sorted by cveId ASC tiebreak)
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-A"))
            .andExpect(jsonPath("$.content[0].kev").value(true))
            .andExpect(jsonPath("$.content[1].cveId").value("CVE-C"))
            .andExpect(jsonPath("$.content[1].kev").value(true))
            // Third is the kev=false row
            .andExpect(jsonPath("$.content[2].cveId").value("CVE-B"))
            .andExpect(jsonPath("$.content[2].kev").value(false));
    }

    /**
     * Test 5 — backward-compat guard. With NO {@code sort} param, the default
     * branch must preserve the DB-side {@code cvssV31Score DESC, cveId ASC}
     * ordering returned by the repository — composite-DESC is opt-in.
     */
    @Test
    void fleetDefaultSortPreservesCvssV31DescBehaviour() throws Exception {
        Cve cveA = buildCve("CVE-A");
        cveA.setId(1L);
        cveA.setCvssV31Score(new BigDecimal("9.0"));
        Cve cveB = buildCve("CVE-B");
        cveB.setId(2L);
        cveB.setCvssV31Score(new BigDecimal("5.0"));
        Cve cveC = buildCve("CVE-C");
        cveC.setId(3L);
        cveC.setCvssV31Score(new BigDecimal("7.0"));

        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(cveA, cveB, cveC));
        // Repo returns rows in CVSS DESC, cveId ASC order (the JPA contract for this finder).
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(1L, 2L, 3L)), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(cveA, cveC, cveB)));

        Map<String, Enrichment> enrichMap = new HashMap<>();
        // Deliberately scramble composite values to prove the default branch does NOT re-sort.
        enrichMap.put("CVE-A", new Enrichment(Boolean.FALSE, null, new BigDecimal("1.00")));
        enrichMap.put("CVE-B", new Enrichment(Boolean.FALSE, null, new BigDecimal("9.99")));
        enrichMap.put("CVE-C", new Enrichment(Boolean.FALSE, null, new BigDecimal("5.00")));
        when(enrichment.enrich(anyCollection(), any(Criticality.class))).thenReturn(enrichMap);

        mockMvc.perform(get("/api/cve/fleet").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            // Order preserved from repo (CVSS DESC: 9.0, 7.0, 5.0) — NOT re-sorted by composite.
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-A"))
            .andExpect(jsonPath("$.content[1].cveId").value("CVE-C"))
            .andExpect(jsonPath("$.content[2].cveId").value("CVE-B"));
    }

    /**
     * review-v44 test-engineer B1 — when {@code kevOnly=true} AND {@code deviceId} is
     * supplied, the controller MUST resolve criticality from the device record (not
     * fall back to the {@code Criticality.MEDIUM} default). Asserts the enrichment
     * service is invoked with the device's actual criticality.
     */
    @Test
    void fleetKevOnly_withDeviceId_resolvesCriticalityFromDevice() throws Exception {
        Device hardenedHost = new Device();
        hardenedHost.setId(42L);
        hardenedHost.setIpAddress("10.0.0.42");
        hardenedHost.setCriticality(Criticality.CRITICAL);
        when(deviceRepository.findById(42L)).thenReturn(Optional.of(hardenedHost));

        when(kevEntryRepository.findAllCveIds()).thenReturn(List.of("CVE-A"));

        Cve cveA = buildCve("CVE-A");
        cveA.setId(7L);
        cveA.setCvssV31Score(new BigDecimal("9.0"));

        // Device 42 has a service that matches CVE-A (FK 7). The kevOnly branch must scope
        // to THIS device's services (findByDeviceId), not the whole fleet.
        NetworkService svc = buildService(70L, 42L, "test", "test", "1.0");
        svc.setName("testsvc");
        when(networkServiceRepository.findByDeviceId(42L)).thenReturn(List.of(svc));
        when(cveMatcher.findVulnerable("cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*"))
            .thenReturn(List.of(cveA));
        when(cveRepository.findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(
                eq(Set.of(7L)), eq(Set.of("CVE-A")), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(cveA)));

        when(enrichment.enrich(anyCollection(), eq(Criticality.CRITICAL)))
            .thenReturn(Map.of("CVE-A",
                new Enrichment(Boolean.TRUE, new BigDecimal("0.40"), new BigDecimal("9.00"))));

        mockMvc.perform(get("/api/cve/fleet")
                .param("kevOnly", "true")
                .param("deviceId", "42")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-A"))
            .andExpect(jsonPath("$.content[0].kev").value(true));

        // deviceId narrows scope to that device's services only.
        verify(networkServiceRepository).findByDeviceId(42L);
        verify(cveRepository).findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(
                eq(Set.of(7L)), eq(Set.of("CVE-A")), any(Pageable.class));
        // Critical assertion — enrichment was invoked with the device's CRITICAL
        // criticality, NOT the MEDIUM default. Proves the kevOnly branch honours
        // the deviceId criticality lookup (analysis Decision 4).
        verify(enrichment).enrich(anyCollection(), eq(Criticality.CRITICAL));
    }

    /**
     * review-v44 test-engineer B2 — explicit null-enrichment guard. The
     * {@code toSummary} fallback ({@code safe = enrichment != null ? ... : new
     * Enrichment(FALSE, null, null)}) must surface a row that has no entry in the
     * enrichment map as {@code kev=false, epssScore=null, compositeScore=null}.
     * Other tests cover this indirectly via {@code stubEnrichmentEmpty()}; this
     * one asserts the wire shape directly.
     */
    @Test
    void fleetWithoutEnrichmentRowsMarshalAsKevFalseEpssNullCompositeNull() throws Exception {
        Cve unenriched = buildCve("CVE-2024-NOENRICH");
        unenriched.setId(999L);
        unenriched.setCvssV31Score(new BigDecimal("7.5"));

        NetworkService svc = buildService(10L, 1L, "test", "test", "1.0");
        svc.setName("testsvc");
        stubFleetService(svc, "cpe:2.3:a:testsvc:testsvc:1.0:*:*:*:*:*:*:*", List.of(unenriched));
        when(cveRepository.findByIdInAndCvssV31ScoreIsNotNull(eq(Set.of(999L)), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(unenriched)));
        // Enrichment service returns an empty map — no entry for CVE-2024-NOENRICH.
        // The controller's safe-fallback must produce kev=false, epssScore=null,
        // compositeScore=null on the wire.
        when(enrichment.enrich(anyCollection(), any(Criticality.class)))
            .thenReturn(Map.of());

        mockMvc.perform(get("/api/cve/fleet").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-2024-NOENRICH"))
            .andExpect(jsonPath("$.content[0].kev").value(false))
            // No global @JsonInclude(NON_NULL) on the controller mapper, so absent
            // enrichment serialises as JSON null (not field-omission). Assert via
            // Hamcrest nullValue() rather than doesNotExist().
            .andExpect(jsonPath("$.content[0].epssScore").value(nullValue()))
            .andExpect(jsonPath("$.content[0].compositeScore").value(nullValue()));
    }

    // ─────────────────────────────────────────────────────────────────────
    // F8 — reverse endpoint GET /api/cve/{cveId}/devices
    // ─────────────────────────────────────────────────────────────────────

    @Test
    void reverseEndpoint_compilationGate_dtoExists() throws Exception {
        // RED: CveAffectedDeviceDto must not yet exist — this test fails to compile
        // until the record is created in Task 1 GREEN.
        io.castellum.web.dto.CveAffectedDeviceDto dto =
            new io.castellum.web.dto.CveAffectedDeviceDto(1L, "host-1", "10.0.0.1", 22, "openssh", "8.2");
        org.junit.jupiter.api.Assertions.assertEquals("host-1", dto.hostname());
    }

    @Test
    void getAffectedDevices_matchingService_returnsDevice() throws Exception {
        // The target CVE exists in the repository.
        Cve cve = buildCve("CVE-2020-15778");
        cve.setId(1L);
        when(cveRepository.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(cve));

        // Fleet has one service whose CPE matches the target CVE.
        NetworkService ssh = buildService(10L, 42L, "openssh", "openssh", "8.2");
        ssh.setName("openssh");
        when(networkServiceRepository.findAll()).thenReturn(List.of(ssh));
        // Matcher returns the target CVE for this CPE.
        when(cveMatcher.findVulnerable("cpe:2.3:a:openssh:openssh:8.2:*:*:*:*:*:*:*"))
                .thenReturn(List.of(cve));

        // Device hydration. The handler hydrates via deviceRepository.findAllById(keySet);
        // match on anyIterable() since the controller passes a Map keySet (not a List).
        Device device = new Device();
        device.setId(42L);
        device.setIpAddress("10.0.0.42");
        device.setCriticality(Criticality.MEDIUM);
        when(deviceRepository.findAllById(anyIterable())).thenReturn(List.of(device));

        mockMvc.perform(get("/api/cve/CVE-2020-15778/devices")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].deviceId").value(42))
                .andExpect(jsonPath("$[0].ipAddress").value("10.0.0.42"))
                .andExpect(jsonPath("$[0].matchedService").value("openssh"))
                .andExpect(jsonPath("$[0].matchedPort").value(22))
                .andExpect(jsonPath("$[0].matchedVersion").value("8.2"));
    }

    @Test
    void getAffectedDevices_nonMatchingService_excluded() throws Exception {
        Cve target = buildCve("CVE-2020-15778");
        target.setId(1L);
        when(cveRepository.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(target));

        // Service whose CPE matches a DIFFERENT CVE (not the target).
        NetworkService other = buildService(20L, 99L, "nginx", "nginx", "1.18");
        other.setName("nginx");
        Cve differentCve = buildCve("CVE-2021-23017");
        differentCve.setId(5L);
        when(networkServiceRepository.findAll()).thenReturn(List.of(other));
        when(cveMatcher.findVulnerable("cpe:2.3:a:nginx:nginx:1.18:*:*:*:*:*:*:*"))
                .thenReturn(List.of(differentCve));

        mockMvc.perform(get("/api/cve/CVE-2020-15778/devices")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    void getAffectedDevices_versionOutsideRange_excluded() throws Exception {
        Cve target = buildCve("CVE-2020-15778");
        target.setId(1L);
        when(cveRepository.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(target));

        // Service version 9.0 — matcher returns empty (out of CVE's affected range).
        NetworkService svc = buildService(30L, 55L, "openssh", "openssh", "9.0");
        svc.setName("openssh");
        when(networkServiceRepository.findAll()).thenReturn(List.of(svc));
        when(cveMatcher.findVulnerable("cpe:2.3:a:openssh:openssh:9.0:*:*:*:*:*:*:*"))
                .thenReturn(List.of()); // version 9.0 not in range → empty

        mockMvc.perform(get("/api/cve/CVE-2020-15778/devices")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    void getAffectedDevices_unknownCveId_returns404() throws Exception {
        when(cveRepository.findByCveId("CVE-9999-9999")).thenReturn(Optional.empty());
        mockMvc.perform(get("/api/cve/CVE-9999-9999/devices")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void getAffectedDevices_viewer_returns200() throws Exception {
        Cve cve = buildCve("CVE-2020-15778");
        cve.setId(1L);
        when(cveRepository.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(cve));
        when(networkServiceRepository.findAll()).thenReturn(List.of());
        mockMvc.perform(get("/api/cve/CVE-2020-15778/devices")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    void getAffectedDevices_anon_returns401() throws Exception {
        mockMvc.perform(get("/api/cve/CVE-2020-15778/devices").with(anonymous()))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Characterises the existing LinkedHashMap first-wins dedup guard.
     * Two services share deviceId 42 but have distinct ports (22 and 8080).
     * Both CPEs match the target CVE. The result must contain exactly one entry
     * (deduplicated) and its matchedPort must be the first service's port (22),
     * proving insertion-order first-wins semantics.
     */
    @Test
    void getAffectedDevices_multipleServicesOnSameDevice_deduplicates() throws Exception {
        Cve target = buildCve("CVE-2020-15778");
        target.setId(1L);
        when(cveRepository.findByCveId("CVE-2020-15778")).thenReturn(Optional.of(target));

        // Two services on the same device, distinct ports.
        NetworkService sshSvc = buildService(10L, 42L, "openssh", "openssh", "8.2");
        sshSvc.setName("openssh");
        sshSvc.setPort(22);

        NetworkService httpSvc = buildService(11L, 42L, "openssh", "openssh", "8.2");
        httpSvc.setName("openssh");
        httpSvc.setPort(8080);

        // Fleet returns both services in insertion order (ssh first).
        when(networkServiceRepository.findAll()).thenReturn(List.of(sshSvc, httpSvc));

        // Both CPEs resolve to the same string and both match the target CVE.
        when(cveMatcher.findVulnerable("cpe:2.3:a:openssh:openssh:8.2:*:*:*:*:*:*:*"))
                .thenReturn(List.of(target));

        Device device = new Device();
        device.setId(42L);
        device.setIpAddress("10.0.0.42");
        device.setCriticality(Criticality.MEDIUM);
        when(deviceRepository.findAllById(anyIterable())).thenReturn(List.of(device));

        mockMvc.perform(get("/api/cve/CVE-2020-15778/devices")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                // Deduped: only one entry for deviceId 42.
                .andExpect(jsonPath("$.length()").value(1))
                // First-wins: matchedPort is 22 (the first service's port).
                .andExpect(jsonPath("$[0].matchedPort").value(22));
    }
}

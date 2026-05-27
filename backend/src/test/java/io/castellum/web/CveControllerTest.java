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

    @Test
    void fleet_default_returnsPageOrderedByScore() throws Exception {
        Cve critical = buildCve("CVE-2024-0001");
        critical.setCvssV31Score(new BigDecimal("9.8"));
        Cve high = buildCve("CVE-2024-0002");
        high.setCvssV31Score(new BigDecimal("7.5"));
        when(cveRepository.findByCvssV31ScoreIsNotNull(any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(critical, high)));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-2024-0001"))
            .andExpect(jsonPath("$.content[1].cveId").value("CVE-2024-0002"))
            .andExpect(jsonPath("$.content[0].rawJson").doesNotExist());

        verify(cveRepository).findByCvssV31ScoreIsNotNull(any(Pageable.class));
    }

    @Test
    void fleet_minScore_filtersBelowFloor() throws Exception {
        Cve high = buildCve("CVE-2024-0010");
        high.setCvssV31Score(new BigDecimal("7.5"));
        when(cveRepository.findByCvssV31ScoreGreaterThanEqual(eq(new BigDecimal("7.0")), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(high)));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet")
                .param("minScore", "7.0")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-2024-0010"));

        verify(cveRepository).findByCvssV31ScoreGreaterThanEqual(eq(new BigDecimal("7.0")), any(Pageable.class));
    }

    @Test
    void fleet_size_clampedTo100() throws Exception {
        when(cveRepository.findByCvssV31ScoreIsNotNull(any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of()));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").param("size", "500"))
            .andExpect(status().isOk());

        org.mockito.ArgumentCaptor<Pageable> captor = org.mockito.ArgumentCaptor.forClass(Pageable.class);
        verify(cveRepository).findByCvssV31ScoreIsNotNull(captor.capture());
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
        when(cveRepository.findByCvssV31ScoreIsNotNull(any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of()));
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
    void fleet_deviceIdAbsent_returnsFullFleetPage_regression() throws Exception {
        Cve cve = buildCve("CVE-2024-0099");
        cve.setCvssV31Score(new BigDecimal("8.1"));
        when(cveRepository.findByCvssV31ScoreIsNotNull(any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(cve)));
        stubEnrichmentEmpty();

        mockMvc.perform(get("/api/cve/fleet").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].cveId").value("CVE-2024-0099"));

        verify(cveRepository).findByCvssV31ScoreIsNotNull(any(Pageable.class));
        verifyNoInteractions(networkServiceRepository);
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
        cve.setCvssV31Score(new BigDecimal("8.0"));
        when(cveRepository.findByCvssV31ScoreIsNotNull(any(Pageable.class)))
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
     * Test 2 — {@code ?kevOnly=true} narrows the result set to KEV-listed CVEs.
     * Verifies the controller pulls the KEV cveId set once and dispatches the
     * {@code findByCveIdInAndCvssV31ScoreIsNotNull} derived query.
     */
    @Test
    void fleetKevOnlyFilterNarrowsResultSet() throws Exception {
        // review-v44 perf-tuner B3 — controller now uses the projected findAllCveIds()
        // to avoid loading every column of every KEV row. Stub the projection directly.
        when(kevEntryRepository.findAllCveIds()).thenReturn(List.of("CVE-A", "CVE-B"));

        Cve cveA = buildCve("CVE-A");
        cveA.setCvssV31Score(new BigDecimal("9.0"));
        Cve cveB = buildCve("CVE-B");
        cveB.setCvssV31Score(new BigDecimal("8.0"));
        when(cveRepository.findByCveIdInAndCvssV31ScoreIsNotNull(eq(Set.of("CVE-A", "CVE-B")), any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(cveA, cveB)));

        Map<String, Enrichment> enrichMap = new HashMap<>();
        enrichMap.put("CVE-A", new Enrichment(Boolean.TRUE, new BigDecimal("0.40"), new BigDecimal("9.00")));
        enrichMap.put("CVE-B", new Enrichment(Boolean.TRUE, new BigDecimal("0.30"), new BigDecimal("8.00")));
        when(enrichment.enrich(anyCollection(), any(Criticality.class))).thenReturn(enrichMap);

        mockMvc.perform(get("/api/cve/fleet").param("kevOnly", "true")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content", hasSize(2)))
            .andExpect(jsonPath("$.content[0].kev").value(true))
            .andExpect(jsonPath("$.content[1].kev").value(true));

        verify(cveRepository).findByCveIdInAndCvssV31ScoreIsNotNull(eq(Set.of("CVE-A", "CVE-B")), any(Pageable.class));
    }

    /**
     * Test 3 — {@code ?sort=composite} orders rows by composite score DESC,
     * exercising the enrichment-window path (fetch wider candidate set, enrich,
     * sort in-memory, slice).
     */
    @Test
    void fleetSortByCompositeReturnsHighestCompositeFirst() throws Exception {
        Cve cveA = buildCve("CVE-A");
        cveA.setCvssV31Score(new BigDecimal("5.0"));
        Cve cveB = buildCve("CVE-B");
        cveB.setCvssV31Score(new BigDecimal("6.0"));
        Cve cveC = buildCve("CVE-C");
        cveC.setCvssV31Score(new BigDecimal("7.0"));
        when(cveRepository.findByCvssV31ScoreIsNotNull(any(Pageable.class)))
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

        // review-v44 test-engineer NB1 — the enrichment-window path MUST request a wider
        // candidate set than the page size so the in-memory sort has enough rows to
        // surface the true top-N. Default request uses size=20; the controller expands
        // to size * ENRICHMENT_WINDOW_MULTIPLIER (= 400) capped at ENRICHMENT_WINDOW_CAP
        // (= 500). Without this assertion the test would also pass on the default branch
        // (`any(Pageable.class)` matches both branches).
        verify(cveRepository).findByCvssV31ScoreIsNotNull(argThat(p -> p.getPageSize() > 20));
    }

    /**
     * Test 4 — {@code ?sort=kev} places KEV-true rows before KEV-false rows.
     * Tiebreak on {@code cveId} ASC ensures determinism per
     * {@code comparatorFor}'s {@code thenComparing(Cve::getCveId)} clause.
     */
    @Test
    void fleetSortByKevPlacesKevTrueRowsFirst() throws Exception {
        Cve cveA = buildCve("CVE-A");
        cveA.setCvssV31Score(new BigDecimal("5.0"));
        Cve cveB = buildCve("CVE-B");
        cveB.setCvssV31Score(new BigDecimal("6.0"));
        Cve cveC = buildCve("CVE-C");
        cveC.setCvssV31Score(new BigDecimal("7.0"));
        when(cveRepository.findByCvssV31ScoreIsNotNull(any(Pageable.class)))
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
     * Test 5 — backward-compat guard (analysis-v38 Decision 5). With NO
     * {@code sort} param, the default branch must preserve the existing DB-side
     * {@code cvssV31Score DESC, cveId ASC} ordering — composite-DESC is opt-in,
     * not a wire-default change.
     */
    @Test
    void fleetDefaultSortPreservesCvssV31DescBehaviour() throws Exception {
        Cve cveA = buildCve("CVE-A");
        cveA.setCvssV31Score(new BigDecimal("9.0"));
        Cve cveB = buildCve("CVE-B");
        cveB.setCvssV31Score(new BigDecimal("5.0"));
        Cve cveC = buildCve("CVE-C");
        cveC.setCvssV31Score(new BigDecimal("7.0"));
        // Repo returns rows in CVSS DESC, cveId ASC order (the JPA contract for this finder
        // when invoked with the default sort spec).
        when(cveRepository.findByCvssV31ScoreIsNotNull(any(Pageable.class)))
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
        cveA.setCvssV31Score(new BigDecimal("9.0"));
        when(cveRepository.findByCveIdInAndCvssV31ScoreIsNotNull(eq(Set.of("CVE-A")), any(Pageable.class)))
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
        unenriched.setCvssV31Score(new BigDecimal("7.5"));
        when(cveRepository.findByCvssV31ScoreIsNotNull(any(Pageable.class)))
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
}

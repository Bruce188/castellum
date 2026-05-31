package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.cve.CveEnrichmentService;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.cve.FleetCveWindowService;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkServiceRepository;
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
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * AC3 — corpus-coverage visibility endpoint contract tests.
 *
 * <p>Verifies that {@code GET /api/cve/coverage} returns the correct JSON shape,
 * computes {@code thinCorpus} correctly for a thin corpus, and enforces RBAC.
 */
@WebMvcTest(CveController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class CveCoverageControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockBean AuditService auditService;
    @MockBean CveRepository cveRepository;
    @MockBean CveMatcher cveMatcher;
    @MockBean NetworkServiceRepository networkServiceRepository;
    @MockBean CveEnrichmentService enrichmentService;
    @MockBean KevEntryRepository kevEntryRepository;
    @MockBean DeviceRepository deviceRepository;
    @MockBean FleetCveWindowService fleetWindowService;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean JwtService jwtService;
    @MockBean UserRepository userRepository;

    @Test
    void coverage_thinCorpus_returnsFlagTrueAndCounts() throws Exception {
        when(cveRepository.count()).thenReturn(3957L);           // < 10 000 → thin
        when(cveRepository.findEarliestPublishedYear()).thenReturn(Optional.of(2026));
        when(cveRepository.findLatestPublishedYear()).thenReturn(Optional.of(2026));  // ≤ 1 year span
        when(kevEntryRepository.countKevInCorpus()).thenReturn(17L);

        mockMvc.perform(get("/api/cve/coverage").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalCves").value(3957))
            .andExpect(jsonPath("$.earliestPublishedYear").value(2026))
            .andExpect(jsonPath("$.latestPublishedYear").value(2026))
            .andExpect(jsonPath("$.kevInCorpus").value(17))
            .andExpect(jsonPath("$.thinCorpus").value(true));
    }

    @Test
    void coverage_fullCorpus_returnsFlagFalse() throws Exception {
        when(cveRepository.count()).thenReturn(250_000L);        // ≥ 10 000 → not thin on count
        when(cveRepository.findEarliestPublishedYear()).thenReturn(Optional.of(2004));
        when(cveRepository.findLatestPublishedYear()).thenReturn(Optional.of(2026));  // span > 1 yr
        when(kevEntryRepository.countKevInCorpus()).thenReturn(1606L);

        mockMvc.perform(get("/api/cve/coverage").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalCves").value(250_000))
            .andExpect(jsonPath("$.earliestPublishedYear").value(2004))
            .andExpect(jsonPath("$.latestPublishedYear").value(2026))
            .andExpect(jsonPath("$.kevInCorpus").value(1606))
            .andExpect(jsonPath("$.thinCorpus").value(false));
    }

    @Test
    void coverage_emptyCorpus_nullYearsAndThin() throws Exception {
        when(cveRepository.count()).thenReturn(0L);
        when(cveRepository.findEarliestPublishedYear()).thenReturn(Optional.empty());
        when(cveRepository.findLatestPublishedYear()).thenReturn(Optional.empty());
        when(kevEntryRepository.countKevInCorpus()).thenReturn(0L);

        mockMvc.perform(get("/api/cve/coverage").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalCves").value(0))
            .andExpect(jsonPath("$.earliestPublishedYear").isEmpty())
            .andExpect(jsonPath("$.latestPublishedYear").isEmpty())
            .andExpect(jsonPath("$.kevInCorpus").value(0))
            .andExpect(jsonPath("$.thinCorpus").value(true));
    }

    @Test
    void coverage_anon_returns401() throws Exception {
        mockMvc.perform(get("/api/cve/coverage").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void coverage_viewer_returns200() throws Exception {
        when(cveRepository.count()).thenReturn(100L);
        when(cveRepository.findEarliestPublishedYear()).thenReturn(Optional.empty());
        when(cveRepository.findLatestPublishedYear()).thenReturn(Optional.empty());
        when(kevEntryRepository.countKevInCorpus()).thenReturn(0L);

        mockMvc.perform(get("/api/cve/coverage").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk());
    }
}

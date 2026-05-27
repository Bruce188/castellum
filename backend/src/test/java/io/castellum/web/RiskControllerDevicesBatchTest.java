package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssScoreRepository;
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
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atMost;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies the batch per-device risk endpoint {@code GET /api/risk/devices?ids=1,2,3}.
 *
 * <p>Contract: returns a JSON object keyed by device id ({@code {"1": {...}}}), one entry per
 * <em>resolvable</em> id (unknown ids omitted), the {@link io.castellum.web.dto.DeviceRiskDto}
 * shape of the single endpoint, ids capped at 200, absent/empty {@code ids} → {@code {}}, same
 * VIEWER/ADMIN authorisation as {@code /api/risk/device/{id}}. The real {@link
 * io.castellum.risk.DeviceRiskService} is imported so resolution runs against the mocked repos
 * and shares the per-device computation with the single endpoint.
 */
@WebMvcTest(controllers = RiskController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class,
    RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class,
    io.castellum.risk.DeviceRiskService.class})
@WithMockUser(roles = "VIEWER")
class RiskControllerDevicesBatchTest {

    @Autowired MockMvc mvc;
    @MockBean CveRepository cveRepo;
    @MockBean DeviceRepository deviceRepo;
    @MockBean EpssScoreRepository epssRepo;
    @MockBean KevEntryRepository kevRepo;
    @MockBean NetworkServiceRepository networkServiceRepository;
    @MockBean CveMatcher cveMatcher;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean JwtService jwtService;
    @MockBean AuditService auditService;
    @MockBean UserRepository userRepository;

    // -----------------------------------------------------------------------
    // Happy path — keyed map, correct shape
    // -----------------------------------------------------------------------

    @Test
    void batch_returnsMapKeyedByDeviceId_withDeviceRiskShape() throws Exception {
        stubDevice(1L, Criticality.MEDIUM);
        stubDevice(2L, Criticality.HIGH);

        mvc.perform(get("/api/risk/devices").param("ids", "1,2"))
           .andExpect(status().isOk())
           // JSON object keyed by id, NOT an array.
           .andExpect(jsonPath("$.1").exists())
           .andExpect(jsonPath("$.2").exists())
           // Each value carries the single-endpoint DeviceRiskDto shape.
           .andExpect(jsonPath("$.1.deviceId").value(1))
           .andExpect(jsonPath("$.1.score").isNumber())
           .andExpect(jsonPath("$.1.topCveIds").isArray())
           .andExpect(jsonPath("$.2.deviceId").value(2));
    }

    // -----------------------------------------------------------------------
    // Unknown ids are omitted (not null entries)
    // -----------------------------------------------------------------------

    @Test
    void batch_omitsUnknownIds() throws Exception {
        stubDevice(1L, Criticality.MEDIUM);
        when(deviceRepo.findById(999L)).thenReturn(Optional.empty());

        mvc.perform(get("/api/risk/devices").param("ids", "1,999"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.1").exists())
           // Unknown id 999 must be absent from the map entirely.
           .andExpect(jsonPath("$.999").doesNotExist());
    }

    // -----------------------------------------------------------------------
    // Absent / empty ids → empty object
    // -----------------------------------------------------------------------

    @Test
    void batch_absentIds_returnsEmptyObject() throws Exception {
        mvc.perform(get("/api/risk/devices"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$").isMap())
           .andExpect(jsonPath("$.*").isEmpty());
        verify(deviceRepo, never()).findById(anyLong());
    }

    @Test
    void batch_emptyIds_returnsEmptyObject() throws Exception {
        mvc.perform(get("/api/risk/devices").param("ids", ""))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.*").isEmpty());
    }

    // -----------------------------------------------------------------------
    // Duplicate ids resolved once
    // -----------------------------------------------------------------------

    @Test
    void batch_deduplicatesRepeatedIds() throws Exception {
        stubDevice(1L, Criticality.MEDIUM);

        mvc.perform(get("/api/risk/devices").param("ids", "1,1,1"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.1").exists());

        // Deduped before resolution — the device is looked up exactly once.
        verify(deviceRepo).findById(1L);
    }

    // -----------------------------------------------------------------------
    // Cap at 200 ids
    // -----------------------------------------------------------------------

    @Test
    void batch_capsIdsAt200() throws Exception {
        // Resolve every id so the only thing limiting work is the cap.
        when(deviceRepo.findById(anyLong())).thenAnswer(inv -> {
            long id = inv.getArgument(0);
            return Optional.of(new Device(id, "10.0.0." + id, "h" + id, null, null, null, Criticality.LOW));
        });
        when(networkServiceRepository.findByDeviceId(anyLong())).thenReturn(List.of());

        // 250 distinct ids — only the first 200 may be processed.
        String ids = IntStream.rangeClosed(1, 250).mapToObj(Integer::toString).collect(Collectors.joining(","));

        mvc.perform(get("/api/risk/devices").param("ids", ids))
           .andExpect(status().isOk())
           // id 1 within the cap is present; id 250 beyond the cap is omitted.
           .andExpect(jsonPath("$.1").exists())
           .andExpect(jsonPath("$.250").doesNotExist());

        // Hard ceiling: never more than 200 device resolutions regardless of input size.
        verify(deviceRepo, atMost(200)).findById(anyLong());
    }

    // -----------------------------------------------------------------------
    // RBAC parity with the single endpoint
    // -----------------------------------------------------------------------

    @Test
    void batch_anon_returns401() throws Exception {
        mvc.perform(get("/api/risk/devices").param("ids", "1").with(anonymous()))
           .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void batch_admin_canRead() throws Exception {
        stubDevice(1L, Criticality.MEDIUM);
        mvc.perform(get("/api/risk/devices").param("ids", "1"))
           .andExpect(status().isOk());
    }

    // -----------------------------------------------------------------------
    // Shared computation — a matched device yields the same score as the single path
    // -----------------------------------------------------------------------

    @Test
    void batch_matchedDevice_carriesScoreAndTopCves() throws Exception {
        Device d = new Device(1L, "10.0.0.1", "h1", null, null, null, Criticality.HIGH);
        when(deviceRepo.findById(1L)).thenReturn(Optional.of(d));
        NetworkService svc = svc(10L, 22, "openssh", "8.2");
        when(networkServiceRepository.findByDeviceId(1L)).thenReturn(List.of(svc));

        Cve hi = makeCve("CVE-2020-15778", 9.8);
        Cve lo = makeCve("CVE-2017-15906", 5.0);
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(hi, lo));
        when(epssRepo.findAllByCveIdIn(any())).thenReturn(List.of());
        when(kevRepo.findAllByCveIdIn(any())).thenReturn(List.of());

        mvc.perform(get("/api/risk/devices").param("ids", "1"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.1.score").isNotEmpty())
           .andExpect(jsonPath("$.1.topCveIds[0]").value("CVE-2020-15778"));
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    private void stubDevice(long id, Criticality crit) {
        Device d = new Device(id, "10.0.0." + id, "host-" + id, null, null, null, crit);
        when(deviceRepo.findById(id)).thenReturn(Optional.of(d));
        when(networkServiceRepository.findByDeviceId(id)).thenReturn(List.of());
    }

    private static Cve makeCve(String id, double cvss) {
        Cve cve = new Cve();
        cve.setCveId(id);
        cve.setCvssV31Score(BigDecimal.valueOf(cvss));
        cve.setRawJson("{}");
        return cve;
    }

    private static NetworkService svc(long id, int port, String name, String version) {
        NetworkService s = new NetworkService();
        s.setId(id);
        s.setDeviceId(1L);
        s.setPort(port);
        s.setProtocol("tcp");
        s.setName(name);
        s.setVersion(version);
        return s;
    }
}

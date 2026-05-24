package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import io.castellum.scan.ScanExecutionService;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ScanController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class ScanControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ScanRepository scanRepository;

    @MockBean
    private AuditService auditService;

    @MockBean
    private ScanExecutionService scanExecutionService;

    @MockBean
    private CastellumUserDetailsService castellumUserDetailsService;
    @MockBean
    JwtService jwtService;
    @MockBean
    UserRepository userRepository;

    @Test
    void postScan_validRequest_returns202WithId() throws Exception {
        Scan saved = new Scan();
        saved.setId(42L);
        saved.setCidr("192.168.1.0/24");
        saved.setScanType("PING_SWEEP");
        saved.setStatus(ScanStatus.PENDING);

        when(scanRepository.save(any(Scan.class))).thenReturn(saved);

        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").value(42));

        verify(auditService).recordEvent(eq("system"), eq("SCAN_SUBMIT"), eq("scan"), anyString(), any());
        verify(scanExecutionService).executeAsync(saved.getId());
    }

    @Test
    void postScan_invalidCidr_returns400() throws Exception {
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"not-a-cidr\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void postScan_invalidType_returns400() throws Exception {
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"INVALID_TYPE\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void list_returnsPaginatedShape() throws Exception {
        when(scanRepository.findAll(any(Pageable.class))).thenReturn(Page.empty());
        mockMvc.perform(get("/api/scans"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content").exists())
            .andExpect(jsonPath("$.totalElements").exists());
    }

    @Test
    void list_respectsPageSize() throws Exception {
        when(scanRepository.findAll(any(Pageable.class))).thenReturn(Page.empty());
        mockMvc.perform(get("/api/scans?size=5&page=0"))
            .andExpect(status().isOk());
        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(scanRepository).findAll(captor.capture());
        assertEquals(5, captor.getValue().getPageSize());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotMutate_returns403() throws Exception {
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"10.0.0.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anon_returns401() throws Exception {
        mockMvc.perform(get("/api/scans").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }
}

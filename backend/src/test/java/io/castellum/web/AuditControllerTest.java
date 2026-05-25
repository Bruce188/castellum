package io.castellum.web;

import io.castellum.audit.AuditEntryDto;
import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditLogRepository;
import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
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
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuditController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class AuditControllerTest {

    @Autowired
    MockMvc mvc;

    @MockBean
    AuditLogRepository repository;

    @MockBean
    AuditService auditService;

    @MockBean
    CastellumUserDetailsService castellumUserDetailsService;

    @MockBean
    JwtService jwtService;

    @MockBean
    UserRepository userRepository;

    @Test
    void anonymousGet_returns401() throws Exception {
        mvc.perform(get("/api/audit").with(anonymous()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerGet_returns403() throws Exception {
        mvc.perform(get("/api/audit"))
            .andExpect(status().isForbidden());
    }

    @Test
    @SuppressWarnings("unchecked")
    void adminGet_empty_returns200WithEmptyPage() throws Exception {
        when(repository.findAll(any(Specification.class), any(Pageable.class)))
            .thenReturn(Page.empty());

        mvc.perform(get("/api/audit"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content").isArray())
            .andExpect(jsonPath("$.content").isEmpty())
            .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    @SuppressWarnings("unchecked")
    void adminGet_sizeOver500_clampsTo500() throws Exception {
        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        when(repository.findAll(any(Specification.class), captor.capture()))
            .thenReturn(Page.empty());

        mvc.perform(get("/api/audit?size=1000"))
            .andExpect(status().isOk());

        assertThat(captor.getValue().getPageSize()).isEqualTo(500);
    }

    @Test
    @SuppressWarnings("unchecked")
    void adminGet_defaultSize_is50() throws Exception {
        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        when(repository.findAll(any(Specification.class), captor.capture()))
            .thenReturn(Page.empty());

        mvc.perform(get("/api/audit"))
            .andExpect(status().isOk());

        assertThat(captor.getValue().getPageSize()).isEqualTo(50);
    }

    @Test
    @SuppressWarnings("unchecked")
    void adminGet_withFilters_passesSpecAndPageable() throws Exception {
        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        when(repository.findAll(any(Specification.class), captor.capture()))
            .thenReturn(Page.empty());

        mvc.perform(get("/api/audit?since=2026-05-01T00:00:00Z&action=SCAN_SUBMIT&size=25"))
            .andExpect(status().isOk());

        Pageable captured = captor.getValue();
        assertThat(captured.getPageSize()).isEqualTo(25);
        assertThat(captured.getSort().toString()).contains("occurredAt: DESC");
    }

    @Test
    @SuppressWarnings("unchecked")
    void adminGet_returnsDtoFields() throws Exception {
        AuditLog log = new AuditLog(
            Instant.parse("2026-05-01T10:00:00Z"),
            "alice", "SCAN_SUBMIT", "scan", "42", null);
        when(repository.findAll(any(Specification.class), any(Pageable.class)))
            .thenReturn((Page) new PageImpl<>(List.of(log)));

        mvc.perform(get("/api/audit"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].actor").value("alice"))
            .andExpect(jsonPath("$.content[0].action").value("SCAN_SUBMIT"))
            .andExpect(jsonPath("$.content[0].occurredAt").exists());
    }
}

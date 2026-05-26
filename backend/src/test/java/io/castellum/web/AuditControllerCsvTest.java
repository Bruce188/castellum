package io.castellum.web;

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuditController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class AuditControllerCsvTest {

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
    @WithMockUser(roles = "VIEWER")
    @SuppressWarnings("unchecked")
    void viewerGet_csv_returns403() throws Exception {
        mvc.perform(get("/api/audit/csv"))
            .andExpect(status().isForbidden());
    }

    @Test
    @SuppressWarnings("unchecked")
    void adminGet_csv_underCap_streamsRows() throws Exception {
        AuditLog row1 = new AuditLog(Instant.parse("2026-05-01T10:00:00Z"), "alice", "SCAN_SUBMIT", "scan", "1", null);
        AuditLog row2 = new AuditLog(Instant.parse("2026-05-02T10:00:00Z"), "bob", "DEVICE_CREATE", "device", "2", null);
        AuditLog rowComma = new AuditLog(Instant.parse("2026-05-03T10:00:00Z"), "carol", "OT_PROBE", "device", "3", "a,b,c");

        when(repository.count(any(Specification.class))).thenReturn(3L);
        when(repository.findAll(any(Specification.class), any(Sort.class)))
            .thenReturn(List.of(row1, row2, rowComma));

        MvcResult started = mvc.perform(get("/api/audit/csv").accept("text/csv"))
            .andExpect(request().asyncStarted())
            .andReturn();

        String contentType = started.getResponse().getContentType();
        assertThat(contentType).startsWith("text/csv");
        String disposition = started.getResponse().getHeader("Content-Disposition");
        assertThat(disposition).isEqualTo("attachment; filename=\"audit-log.csv\"");

        MvcResult result = mvc.perform(asyncDispatch(started))
            .andExpect(status().isOk())
            .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).startsWith("id,occurredAt,actor,action,resourceType,resourceId,payload\n");
        // The comma-containing payload should be quoted
        assertThat(body).contains("\"a,b,c\"");
    }

    @Test
    @SuppressWarnings("unchecked")
    void adminGet_csv_overCap_returns413() throws Exception {
        when(repository.count(any(Specification.class))).thenReturn(10001L);

        mvc.perform(get("/api/audit/csv"))
            .andExpect(status().is(413))
            .andExpect(jsonPath("$.error").value("csv_cap_exceeded"))
            .andExpect(jsonPath("$.filteredCount").value(10001))
            .andExpect(jsonPath("$.limit").value(10000));
    }

    @Test
    @SuppressWarnings("unchecked")
    void adminGet_csv_empty_returns200WithJustHeader() throws Exception {
        when(repository.count(any(Specification.class))).thenReturn(0L);
        when(repository.findAll(any(Specification.class), any(Sort.class)))
            .thenReturn(List.of());

        MvcResult started = mvc.perform(get("/api/audit/csv").accept("text/csv"))
            .andExpect(request().asyncStarted())
            .andReturn();

        MvcResult result = mvc.perform(asyncDispatch(started))
            .andExpect(status().isOk())
            .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).isEqualTo("id,occurredAt,actor,action,resourceType,resourceId,payload\n");
    }

    @Test
    void csvEscape_handlesCommaQuoteNewline() {
        assertThat(AuditController.csvEscape("a,b")).isEqualTo("\"a,b\"");
        assertThat(AuditController.csvEscape("a\"b")).isEqualTo("\"a\"\"b\"");
        assertThat(AuditController.csvEscape(null)).isEqualTo("");
        assertThat(AuditController.csvEscape("plain")).isEqualTo("plain");
        assertThat(AuditController.csvEscape("line\nnewline")).isEqualTo("\"line\nnewline\"");
    }
}

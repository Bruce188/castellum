package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.risk.FeedSyncSchedule;
import io.castellum.risk.FeedSyncScheduleRepository;
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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(FeedScheduleController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class,
        RbacAuthenticationEntryPoint.class, GlobalExceptionHandler.class,
        FeedScheduleControllerTest.ClockConfig.class})
class FeedScheduleControllerTest {

    /** Fixed clock at 2026-05-28T00:00:00Z — used when the row has no lastRunAt. */
    static final Instant FIXED_NOW = Instant.parse("2026-05-28T00:00:00Z");

    static class ClockConfig {
        @Bean
        Clock clock() {
            return Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private FeedSyncScheduleRepository repository;

    @MockBean
    private AuditService auditService;

    @MockBean
    private CastellumUserDetailsService castellumUserDetailsService;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private UserRepository userRepository;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private FeedSyncSchedule seededRow() {
        FeedSyncSchedule row = new FeedSyncSchedule();
        row.setId(FeedSyncSchedule.SINGLETON_ID);
        row.setEnabled(true);
        row.setCronExpression("0 0 6 * * *");
        // lastRunAt yesterday at 06:00 UTC — nextRunAt must be today 06:00 UTC
        row.setLastRunAt(Instant.parse("2026-05-27T06:00:00Z"));
        row.setLastStatus("OK");
        row.setLastError(null);
        row.setConsecutiveFailures(0);
        row.setRetryAfterAt(null);
        row.setCreatedAt(Instant.parse("2026-05-01T00:00:00Z"));
        return row;
    }

    private FeedSyncSchedule rowWithRetry(Instant retryAfterAt) {
        FeedSyncSchedule row = seededRow();
        row.setLastStatus("FAILED");
        row.setConsecutiveFailures(1);
        row.setRetryAfterAt(retryAfterAt);
        return row;
    }

    // -----------------------------------------------------------------------
    // Case 1 — ADMIN GET returns schedule with computed nextRunAt
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_get_returnsScheduleWithNextRunAt() throws Exception {
        when(repository.findById(FeedSyncSchedule.SINGLETON_ID))
                .thenReturn(Optional.of(seededRow()));

        mockMvc.perform(get("/api/admin/feed-schedule"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.cron").value("0 0 6 * * *"))
                .andExpect(jsonPath("$.consecutiveFailures").value(0))
                // nextRunAt must be present and non-null (next 06:00 UTC after 2026-05-27T06:00:00Z)
                .andExpect(jsonPath("$.nextRunAt").isNotEmpty())
                // Expected next run: 2026-05-28T06:00:00Z
                .andExpect(jsonPath("$.nextRunAt").value("2026-05-28T06:00:00Z"));
    }

    // -----------------------------------------------------------------------
    // Case 2 — ADMIN GET honours pending retry (retryAfterAt < cronNext)
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_get_nextRunAt_honoursRetryAfterAtWhenEarlierThanCronNext() throws Exception {
        // retryAfterAt is 2026-05-28T03:00:00Z — earlier than cron-next (06:00)
        Instant earlyRetry = Instant.parse("2026-05-28T03:00:00Z");
        when(repository.findById(FeedSyncSchedule.SINGLETON_ID))
                .thenReturn(Optional.of(rowWithRetry(earlyRetry)));

        mockMvc.perform(get("/api/admin/feed-schedule"))
                .andExpect(status().isOk())
                // nextRunAt must equal the earlier retryAfterAt
                .andExpect(jsonPath("$.nextRunAt").value("2026-05-28T03:00:00Z"));
    }

    // -----------------------------------------------------------------------
    // Case 3 — ADMIN PUT updates cron + enabled + audits
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_put_updatesCronAndEnabled() throws Exception {
        FeedSyncSchedule existing = seededRow();
        when(repository.findById(FeedSyncSchedule.SINGLETON_ID))
                .thenReturn(Optional.of(existing));
        when(repository.save(any(FeedSyncSchedule.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(put("/api/admin/feed-schedule")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false,\"cron\":\"0 0 3 * * *\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.cron").value("0 0 3 * * *"));

        verify(repository).save(argThat(row ->
                !row.isEnabled() && "0 0 3 * * *".equals(row.getCronExpression())));
        verify(auditService).recordEvent(
                eq("admin"),
                eq("FEED_SCHEDULE_UPDATE"),
                eq("feed_schedule"),
                eq("1"),
                any());
    }

    // -----------------------------------------------------------------------
    // Case 4 — ADMIN PUT malformed cron → 400
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_put_malformedCron_returns400() throws Exception {
        mockMvc.perform(put("/api/admin/feed-schedule")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":true,\"cron\":\"not-a-cron\"}"))
                .andExpect(status().isBadRequest());

        verify(repository, never()).save(any());
    }

    // -----------------------------------------------------------------------
    // Case 5a — ADMIN PUT /enable flips enabled=true + audits
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_enable_setsEnabledTrue_andAudits() throws Exception {
        FeedSyncSchedule existing = seededRow();
        existing.setEnabled(false);
        when(repository.findById(FeedSyncSchedule.SINGLETON_ID))
                .thenReturn(Optional.of(existing));
        when(repository.save(any(FeedSyncSchedule.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(put("/api/admin/feed-schedule/enable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true));

        verify(repository).save(argThat(FeedSyncSchedule::isEnabled));
        verify(auditService).recordEvent(
                eq("admin"),
                eq("FEED_SCHEDULE_UPDATE"),
                eq("feed_schedule"),
                eq("1"),
                any());
    }

    // -----------------------------------------------------------------------
    // Case 5b — ADMIN PUT /disable flips enabled=false + audits
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_disable_setsEnabledFalse_andAudits() throws Exception {
        FeedSyncSchedule existing = seededRow();
        when(repository.findById(FeedSyncSchedule.SINGLETON_ID))
                .thenReturn(Optional.of(existing));
        when(repository.save(any(FeedSyncSchedule.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(put("/api/admin/feed-schedule/disable"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));

        verify(repository).save(argThat(row -> !row.isEnabled()));
        verify(auditService).recordEvent(
                eq("admin"),
                eq("FEED_SCHEDULE_UPDATE"),
                eq("feed_schedule"),
                eq("1"),
                any());
    }

    // -----------------------------------------------------------------------
    // Case 6 — VIEWER → 403 on GET and PUT
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_get_returns403() throws Exception {
        mockMvc.perform(get("/api/admin/feed-schedule"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_put_returns403() throws Exception {
        mockMvc.perform(put("/api/admin/feed-schedule")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false,\"cron\":\"0 0 6 * * *\"}"))
                .andExpect(status().isForbidden());
    }

    // -----------------------------------------------------------------------
    // Case 7 — anonymous → 401
    // -----------------------------------------------------------------------

    @Test
    void anon_get_returns401() throws Exception {
        mockMvc.perform(get("/api/admin/feed-schedule").with(anonymous()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void anon_put_returns401() throws Exception {
        mockMvc.perform(put("/api/admin/feed-schedule")
                        .with(anonymous())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":true,\"cron\":\"0 0 6 * * *\"}"))
                .andExpect(status().isUnauthorized());
    }

    // -----------------------------------------------------------------------
    // Case 8 — ADMIN PUT /reset restores DEFAULT_CRON + audits
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(roles = "ADMIN", username = "admin")
    void admin_reset_restoresDefaultCron_andAudits() throws Exception {
        FeedSyncSchedule existing = seededRow();
        existing.setCronExpression("0 0 3 * * *"); // some custom cron
        when(repository.findById(FeedSyncSchedule.SINGLETON_ID))
                .thenReturn(Optional.of(existing));
        when(repository.save(any(FeedSyncSchedule.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(put("/api/admin/feed-schedule/reset"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cron").value(FeedSyncSchedule.DEFAULT_CRON));

        verify(repository).save(argThat(row ->
                FeedSyncSchedule.DEFAULT_CRON.equals(row.getCronExpression())));
        verify(auditService).recordEvent(
                eq("admin"),
                eq("FEED_SCHEDULE_RESET"),
                eq("feed_schedule"),
                eq("1"),
                any());
    }

    // -----------------------------------------------------------------------
    // Case 9 — VIEWER → 403 on reset
    // -----------------------------------------------------------------------

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_reset_returns403() throws Exception {
        mockMvc.perform(put("/api/admin/feed-schedule/reset"))
                .andExpect(status().isForbidden());
    }

    // -----------------------------------------------------------------------
    // Case 10 — anonymous → 401 on reset
    // -----------------------------------------------------------------------

    @Test
    void anon_reset_returns401() throws Exception {
        mockMvc.perform(put("/api/admin/feed-schedule/reset").with(anonymous()))
                .andExpect(status().isUnauthorized());
    }
}

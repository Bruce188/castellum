package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import({io.castellum.config.SecurityConfig.class,
    io.castellum.security.JwtAuthenticationFilter.class,
    io.castellum.security.RbacAccessDeniedHandler.class,
    io.castellum.security.RbacAuthenticationEntryPoint.class,
    io.castellum.web.GlobalExceptionHandler.class})
class AuthControllerChangePasswordTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    @MockBean AuthenticationManager authManager;
    @MockBean JwtService jwtService;
    @MockBean AuditService auditService;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean UserRepository userRepository;
    @MockBean LoginRateLimiter loginRateLimiter;
    @MockBean ClientAddressResolver clientAddressResolver;
    @MockBean PasswordChangeRateLimiter passwordChangeRateLimiter;
    @MockBean PasswordEncoder passwordEncoder;

    @BeforeEach
    void permitRateLimit() {
        when(passwordChangeRateLimiter.tryAcquire(any())).thenReturn(true);
    }

    @Test
    @WithMockUser(username = "alice", roles = "VIEWER")
    void changePassword_correctOld_returns204_andBumpsTokenVersion() throws Exception {
        User u = new User("alice", "$2a$12$existing-hash", Role.VIEWER, true, Instant.now());
        u.setTokenVersion(5);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("oldpass", "$2a$12$existing-hash")).thenReturn(true);
        when(passwordEncoder.encode("newpassword123")).thenReturn("$2a$12$new-hash");

        mvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"oldpass\",\"newPassword\":\"newpassword123\"}"))
            .andExpect(status().isNoContent());

        assertThat(u.getPasswordHash()).isEqualTo("$2a$12$new-hash");
        assertThat(u.getTokenVersion()).isEqualTo(6);
        verify(userRepository).save(u);
        verify(auditService).recordEvent(eq("alice"), eq("AUTH_PASSWORD_CHANGE"), eq("user"), any(), any());
        verify(passwordChangeRateLimiter).recordAttempt("alice");
    }

    @Test
    @WithMockUser(username = "alice", roles = "VIEWER")
    void changePassword_wrongOld_returns401_andAudits_andDoesNotPersist() throws Exception {
        User u = new User("alice", "$2a$12$existing-hash", Role.VIEWER, true, Instant.now());
        u.setTokenVersion(5);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", "$2a$12$existing-hash")).thenReturn(false);

        mvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"wrong\",\"newPassword\":\"newpassword123\"}"))
            .andExpect(status().isUnauthorized());

        assertThat(u.getPasswordHash()).isEqualTo("$2a$12$existing-hash");
        assertThat(u.getTokenVersion()).isEqualTo(5);
        verify(userRepository, never()).save(any());
        verify(auditService).recordEvent(eq("alice"), eq("AUTH_PASSWORD_CHANGE_DENIED"),
            eq("user"), any(), any());
        // budget still spent — brute-force attempts must count
        verify(passwordChangeRateLimiter).recordAttempt("alice");
    }

    @Test
    @WithMockUser(username = "alice", roles = "VIEWER")
    void changePassword_overBudget_returns429_withRetryAfter() throws Exception {
        when(passwordChangeRateLimiter.tryAcquire("alice")).thenReturn(false);
        when(passwordChangeRateLimiter.retryAfterSeconds("alice")).thenReturn(42L);

        mvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"x\",\"newPassword\":\"newpassword123\"}"))
            .andExpect(status().is(429))
            .andExpect(header().string("Retry-After", "42"));

        verify(auditService).recordEvent(eq("alice"), eq("AUTH_PASSWORD_CHANGE_RATE_LIMIT"),
            eq("auth"), any(), any());
        verify(userRepository, never()).findByUsername(any());
    }

    @Test
    void changePassword_anonymous_returns401() throws Exception {
        // No @WithMockUser → no SecurityContext → entry point fires 401.
        mvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"x\",\"newPassword\":\"newpassword123\"}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "alice", roles = "VIEWER")
    void changePassword_shortNewPassword_returns400() throws Exception {
        mvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"x\",\"newPassword\":\"short\"}"))
            .andExpect(status().isBadRequest());

        verify(userRepository, never()).findByUsername(any());
    }

    @Test
    @WithMockUser(username = "alice", roles = "VIEWER")
    void changePassword_blankOld_returns400() throws Exception {
        mvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"\",\"newPassword\":\"validnewpass\"}"))
            .andExpect(status().isBadRequest());
    }
}

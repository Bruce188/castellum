package io.castellum.security;

import io.castellum.audit.AuditService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@Import({io.castellum.config.SecurityConfig.class,
    io.castellum.security.JwtAuthenticationFilter.class,
    io.castellum.security.RbacAccessDeniedHandler.class,
    io.castellum.security.RbacAuthenticationEntryPoint.class,
    io.castellum.web.GlobalExceptionHandler.class})
class UserControllerRoleChangeTest {

    @Autowired MockMvc mvc;

    @MockBean UserRepository userRepository;
    @MockBean AuditService auditService;
    @MockBean JwtService jwtService;
    @MockBean LoginRateLimiter loginRateLimiter;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean PasswordEncoder passwordEncoder;

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    void adminCanChangeRole_returns200_bumpsTokenVersion_audits() throws Exception {
        User alice = new User("alice", "$2a$12$x", Role.VIEWER, true, Instant.now());
        alice.setTokenVersion(2);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));

        mvc.perform(put("/api/users/alice/role")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\":\"ADMIN\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("alice"))
            .andExpect(jsonPath("$.role").value("ADMIN"))
            .andExpect(jsonPath("$.passwordHash").doesNotExist());

        assertThat(alice.getRole()).isEqualTo(Role.ADMIN);
        assertThat(alice.getTokenVersion()).isEqualTo(3);
        verify(auditService).recordEvent(eq("admin"), eq("USER_ROLE_CHANGE"), eq("user"), any(), any());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotChangeRole_returns403() throws Exception {
        mvc.perform(put("/api/users/alice/role")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\":\"ADMIN\"}"))
            .andExpect(status().isForbidden());

        verify(userRepository, never()).save(any());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void roleChange_unknownUser_returns404() throws Exception {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        mvc.perform(put("/api/users/ghost/role")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"role\":\"VIEWER\"}"))
            .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void roleChange_missingBody_returns400() throws Exception {
        mvc.perform(put("/api/users/alice/role")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isBadRequest());
    }
}

package io.castellum.security;

import io.castellum.audit.AuditService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@Import({io.castellum.config.SecurityConfig.class,
        io.castellum.security.JwtAuthenticationFilter.class,
        io.castellum.security.RbacAccessDeniedHandler.class,
        io.castellum.security.RbacAuthenticationEntryPoint.class})
class UserControllerTest {

    @Autowired
    MockMvc mvc;

    @MockBean
    UserRepository userRepository;

    @MockBean
    AuditService auditService;

    @MockBean
    JwtService jwtService;

    @MockBean
    LoginRateLimiter loginRateLimiter;

    @MockBean
    CastellumUserDetailsService castellumUserDetailsService;

    @MockBean
    org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminCanDisableUser() throws Exception {
        User u = new User("alice", "$2a$12$x", Role.VIEWER, true, Instant.now());
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));

        mvc.perform(post("/api/users/alice/disable"))
            .andExpect(status().isNoContent());

        assertThat(u.isEnabled()).isFalse();
        assertThat(u.getTokenVersion()).isEqualTo(1);
        verify(auditService).recordEvent(any(), eq("USER_DISABLED"), eq("user"), eq("alice"), any());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotDisableUser() throws Exception {
        mvc.perform(post("/api/users/alice/disable"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anonymousCannotDisableUser() throws Exception {
        mvc.perform(post("/api/users/alice/disable"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void disableMissingUserReturns404() throws Exception {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        mvc.perform(post("/api/users/ghost/disable"))
            .andExpect(status().isNotFound());
    }
}

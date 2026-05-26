package io.castellum.security;

import io.castellum.audit.AuditService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@Import({io.castellum.config.SecurityConfig.class,
    io.castellum.security.JwtAuthenticationFilter.class,
    io.castellum.security.RbacAccessDeniedHandler.class,
    io.castellum.security.RbacAuthenticationEntryPoint.class,
    io.castellum.web.GlobalExceptionHandler.class})
class UserControllerListTest {

    @Autowired MockMvc mvc;

    @MockBean UserRepository userRepository;
    @MockBean AuditService auditService;
    @MockBean JwtService jwtService;
    @MockBean LoginRateLimiter loginRateLimiter;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean PasswordEncoder passwordEncoder;

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminCanListUsers_returns200_paginated_excludesPasswordHash() throws Exception {
        User a = new User("alice", "$2a$12$secret-hash-A", Role.VIEWER, true, Instant.now());
        User b = new User("bob", "$2a$12$secret-hash-B", Role.ADMIN, true, Instant.now());
        when(userRepository.findAll(any(Pageable.class)))
            .thenReturn(new PageImpl<>(List.of(a, b)));

        mvc.perform(get("/api/users?page=0&size=10"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].username").value("alice"))
            .andExpect(jsonPath("$.content[0].passwordHash").doesNotExist())
            .andExpect(jsonPath("$.content[1].username").value("bob"))
            .andExpect(jsonPath("$.totalElements").value(2));
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotListUsers_returns403() throws Exception {
        mvc.perform(get("/api/users"))
            .andExpect(status().isForbidden());
    }

    @Test
    void anonymousCannotListUsers_returns401() throws Exception {
        mvc.perform(get("/api/users"))
            .andExpect(status().isUnauthorized());
    }
}

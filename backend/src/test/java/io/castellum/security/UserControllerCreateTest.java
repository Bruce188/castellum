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

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@Import({io.castellum.config.SecurityConfig.class,
    io.castellum.security.JwtAuthenticationFilter.class,
    io.castellum.security.RbacAccessDeniedHandler.class,
    io.castellum.security.RbacAuthenticationEntryPoint.class,
    io.castellum.web.GlobalExceptionHandler.class})
class UserControllerCreateTest {

    @Autowired MockMvc mvc;

    @MockBean UserRepository userRepository;
    @MockBean AuditService auditService;
    @MockBean JwtService jwtService;
    @MockBean LoginRateLimiter loginRateLimiter;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean PasswordEncoder passwordEncoder;

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    void adminCanCreateUser_returns201_andAuditsAndPersistsBcryptHash() throws Exception {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("initial-pwd!")).thenReturn("$2a$12$bcrypt-result");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            // simulate persistence assigning id
            try {
                var f = User.class.getDeclaredField("id");
                f.setAccessible(true);
                f.set(u, 99L);
            } catch (Exception e) { /* not load-bearing */ }
            return u;
        });

        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"role\":\"VIEWER\",\"initialPassword\":\"initial-pwd!\"}"))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.username").value("alice"))
            .andExpect(jsonPath("$.role").value("VIEWER"))
            .andExpect(jsonPath("$.enabled").value(true))
            .andExpect(jsonPath("$.passwordHash").doesNotExist());

        verify(passwordEncoder).encode("initial-pwd!");
        verify(userRepository).save(argThat(u ->
            "alice".equals(u.getUsername())
            && Role.VIEWER == u.getRole()
            && "$2a$12$bcrypt-result".equals(u.getPasswordHash())
            && u.isEnabled()
            && u.getTokenVersion() == 0));
        verify(auditService).recordEvent(eq("admin"), eq("USER_CREATE"), eq("user"), any(), any());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    void duplicateUsername_returns409() throws Exception {
        User existing = new User("alice", "$2a$12$x", Role.ADMIN, true, Instant.now());
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(existing));

        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"role\":\"VIEWER\",\"initialPassword\":\"initial-pwd!\"}"))
            .andExpect(status().isConflict());

        verify(userRepository, never()).save(any());
        verify(auditService, never()).recordEvent(any(), eq("USER_CREATE"), any(), any(), any());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewerCannotCreateUser_returns403() throws Exception {
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"role\":\"VIEWER\",\"initialPassword\":\"initial-pwd!\"}"))
            .andExpect(status().isForbidden());

        verify(userRepository, never()).save(any());
    }

    @Test
    void anonymousCannotCreateUser_returns401() throws Exception {
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"role\":\"VIEWER\",\"initialPassword\":\"initial-pwd!\"}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void createUser_shortPassword_returns400() throws Exception {
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"role\":\"VIEWER\",\"initialPassword\":\"short\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void createUser_invalidUsernameChar_returns400() throws Exception {
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice@evil\",\"role\":\"VIEWER\",\"initialPassword\":\"initial-pwd!\"}"))
            .andExpect(status().isBadRequest());
    }
}

package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditService;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import({io.castellum.config.SecurityConfig.class, io.castellum.security.JwtAuthenticationFilter.class,
    io.castellum.security.RbacAccessDeniedHandler.class, io.castellum.security.RbacAuthenticationEntryPoint.class})
class AuthControllerTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper om;

    @MockBean
    AuthenticationManager authManager;

    @MockBean
    JwtService jwtService;

    @MockBean
    AuditService auditService;

    @MockBean
    CastellumUserDetailsService castellumUserDetailsService;

    @Test
    void validCredentialsReturns200WithToken() throws Exception {
        var authResult = new UsernamePasswordAuthenticationToken(
            "alice", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        when(authManager.authenticate(any())).thenReturn(authResult);
        when(jwtService.issueToken(eq("alice"), anyList())).thenReturn("jwt-fixture");
        when(jwtService.ttlSeconds()).thenReturn(3600L);

        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"pw\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("jwt-fixture"))
            .andExpect(jsonPath("$.roles[0]").value("ADMIN"));

        verify(auditService).recordEvent(eq("alice"), eq("LOGIN_SUCCESS"), eq("auth"), eq("alice"), any());
    }

    @Test
    void badPasswordReturns401AndAuditsLoginFail() throws Exception {
        when(authManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"wrong\"}"))
            .andExpect(status().isUnauthorized());

        verify(auditService).recordEvent(eq("alice"), eq("LOGIN_FAIL"), eq("auth"), eq("alice"), any());
    }

    @Test
    void unknownUserReturns401AndAuditsLoginFail() throws Exception {
        when(authManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"ghost\",\"password\":\"pw\"}"))
            .andExpect(status().isUnauthorized());

        verify(auditService).recordEvent(eq("ghost"), eq("LOGIN_FAIL"), eq("auth"), eq("ghost"), any());
    }

    @Test
    void missingBodyReturns400() throws Exception {
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest());
    }

    @Test
    @Disabled("rate-limit deferred to follow-up")
    void placeholderRateLimitTestSkipped() {
        throw new UnsupportedOperationException("rate-limit not implemented; do not remove @Disabled without implementation");
    }
}

package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.hamcrest.Matchers.startsWith;
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

    @MockBean
    UserRepository userRepository;

    @MockBean
    LoginRateLimiter rateLimiter;

    @BeforeEach
    void setupRateLimiter() {
        when(rateLimiter.tryAcquire(any())).thenReturn(true);
    }

    @SuppressWarnings("unchecked")
    @Test
    void validCredentialsReturns200WithToken() throws Exception {
        Instant fixedExp = Instant.parse("2026-05-24T18:00:00Z");
        Jws<Claims> mockJws = mock(Jws.class);
        Claims mockClaims = mock(Claims.class);
        when(mockJws.getPayload()).thenReturn(mockClaims);
        when(mockClaims.getExpiration()).thenReturn(Date.from(fixedExp));

        var authResult = new UsernamePasswordAuthenticationToken(
            "alice", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        when(authManager.authenticate(any())).thenReturn(authResult);
        when(jwtService.issueToken(eq("alice"), anyList())).thenReturn("jwt-fixture");
        when(jwtService.parse("jwt-fixture")).thenReturn(mockJws);

        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"pw\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("jwt-fixture"))
            .andExpect(jsonPath("$.roles[0]").value("ADMIN"))
            .andExpect(jsonPath("$.expiresAt").value(startsWith("2026-05-24T18:00:00")));

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
    void eleventhLoginInWindowReturns429WithRetryAfter() throws Exception {
        when(rateLimiter.tryAcquire(any())).thenReturn(false);
        when(rateLimiter.retryAfterSeconds(any())).thenReturn(45L);

        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"pw\"}"))
            .andExpect(status().is(429))
            .andExpect(header().string("Retry-After", "45"));

        verify(auditService).recordEvent(any(), eq("LOGIN_RATE_LIMIT"), eq("auth"), any(), any());
    }

    @Test
    void login_disabledUser_returnsUnauthorized() throws Exception {
        when(authManager.authenticate(any())).thenThrow(new DisabledException("user disabled"));

        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"disabled-user\",\"password\":\"anything\"}"))
            .andExpect(status().isUnauthorized());

        verify(jwtService, never()).issueToken(any(), any());
        verify(jwtService, never()).issueToken(any(), any(), anyInt());
    }

    @SuppressWarnings("unchecked")
    @Test
    void successfulLoginsDoNotConsumeRateLimit() throws Exception {
        Jws<Claims> mockJws = mock(Jws.class);
        Claims mockClaims = mock(Claims.class);
        when(mockJws.getPayload()).thenReturn(mockClaims);
        when(mockClaims.getExpiration()).thenReturn(Date.from(Instant.now().plusSeconds(3600)));

        var authResult = new UsernamePasswordAuthenticationToken(
            "alice", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        when(authManager.authenticate(any())).thenReturn(authResult);
        when(jwtService.issueToken(eq("alice"), anyList())).thenReturn("jwt-fixture");
        when(jwtService.parse("jwt-fixture")).thenReturn(mockJws);

        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"pw\"}"))
            .andExpect(status().isOk());

        verify(rateLimiter, never()).recordFailure(any());
    }
}

package io.castellum.security;

import io.castellum.audit.AuditService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {

    private static final String TEST_SECRET = "test-secret-test-secret-test-secret-1234";

    private JwtService jwtService() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("test");
        return new JwtService(TEST_SECRET, 3600, env);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validBearerTokenSetsSecurityContext() throws Exception {
        JwtService svc = jwtService();
        String token = svc.issueToken("alice", List.of("ADMIN"));

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth);
        assertEquals("alice", auth.getName());
        assertTrue(auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void missingHeaderPassesThrough() throws Exception {
        JwtService svc = jwtService();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc);
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void invalidTokenLeavesContextUnauthenticated() throws Exception {
        JwtService svc = jwtService();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer not-a-token");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        // chain must have proceeded
        assertNotNull(chain.getRequest(), "chain.doFilter must be invoked");
    }

    @Test
    void expiredTokenLeavesContextUnauthenticated() throws Exception {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("test");
        JwtService svc = new JwtService(TEST_SECRET, 1, env);
        String token = svc.issueToken("alice", List.of("ADMIN"));
        Thread.sleep(2500);

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertNotNull(chain.getRequest(), "chain.doFilter must be invoked even on expired token");
    }

    @Test
    void tokenVersionMismatchClearsContext() throws Exception {
        JwtService svc = jwtService();
        // Issue a token with tv=0
        String token = svc.issueToken("alice", List.of("VIEWER"), 0);

        AuditService auditService = mock(AuditService.class);
        UserRepository userRepository = mock(UserRepository.class);
        // User has tokenVersion=1 in DB, token has tv=0 → mismatch
        User user = new User("alice", "$2a$12$x", Role.VIEWER, true, Instant.now());
        user.setTokenVersion(1);
        when(userRepository.findByUsernameAndEnabledTrue(eq("alice"))).thenReturn(Optional.of(user));

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc, auditService, userRepository);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication(),
            "context must be cleared on token_version mismatch");
        verify(auditService).recordEvent(eq("alice"), eq("AUTH_TOKEN_REJECT"), eq("auth"), eq(null),
            argThat(p -> p instanceof Map<?,?> m && "token_version_mismatch".equals(m.get("reason"))));
    }

    @Test
    void disabledOrMissingUserClearsContext() throws Exception {
        JwtService svc = jwtService();
        String token = svc.issueToken("bob", List.of("VIEWER"), 0);

        AuditService auditService = mock(AuditService.class);
        UserRepository userRepository = mock(UserRepository.class);
        when(userRepository.findByUsernameAndEnabledTrue(any())).thenReturn(Optional.empty());

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc, auditService, userRepository);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication(),
            "context must be cleared when user is disabled or missing");
        verify(auditService).recordEvent(eq("bob"), eq("AUTH_TOKEN_REJECT"), eq("auth"), eq(null),
            argThat(p -> p instanceof Map<?,?> m && "user_disabled_or_missing".equals(m.get("reason"))));
    }
}

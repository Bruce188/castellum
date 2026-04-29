package io.castellum.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

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
        Thread.sleep(1500);

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertNotNull(chain.getRequest(), "chain.doFilter must be invoked even on expired token");
    }
}

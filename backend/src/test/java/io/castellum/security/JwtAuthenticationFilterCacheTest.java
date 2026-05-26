package io.castellum.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Verifies that {@link JwtAuthenticationFilter} parses the JWT token
 * exactly once per request by caching the {@link Jws} under a request attribute.
 */
class JwtAuthenticationFilterCacheTest {

    private static final String TEST_SECRET = "test-secret-test-secret-test-secret-1234";
    private static final String ATTR = "io.castellum.security.jwtClaims";

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private JwtService realJwtService() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("test");
        return new JwtService(TEST_SECRET, 3600, env);
    }

    @Test
    void filterCallsExtractClaimsExactlyOncePerRequest() throws Exception {
        JwtService realSvc = realJwtService();
        String token = realSvc.issueToken("alice", List.of("ADMIN"));

        // Spy on the real service so we can verify call counts without breaking behaviour
        JwtService spySvc = spy(realSvc);

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(spySvc);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        // extractClaims must be called exactly once despite multiple claim reads
        verify(spySvc, times(1)).extractClaims(token);
    }

    @Test
    void cachedJwsStoredOnRequestAttribute() throws Exception {
        JwtService svc = realJwtService();
        String token = svc.issueToken("bob", List.of("VIEWER"));

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        Object attr = req.getAttribute(ATTR);
        assertNotNull(attr, "Parsed Jws must be stored under request attribute " + ATTR);
        assertTrue(attr instanceof Jws<?>, "Attribute must be a Jws instance");

        @SuppressWarnings("unchecked")
        Jws<Claims> jws = (Jws<Claims>) attr;
        assertEquals("bob", jws.getPayload().getSubject());
    }

    @Test
    void missingTokenDoesNotSetRequestAttribute() throws Exception {
        JwtService svc = realJwtService();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc);
        MockHttpServletRequest req = new MockHttpServletRequest();
        // No Authorization header
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        assertNull(req.getAttribute(ATTR),
                "No attribute must be set when Authorization header is absent");
    }

    @Test
    void invalidTokenDoesNotSetRequestAttribute() throws Exception {
        JwtService svc = realJwtService();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(svc);
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer not-a-valid-token");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(req, res, chain);

        assertNull(req.getAttribute(ATTR),
                "No attribute must be set when token parsing fails");
    }

    @Test
    void existingConstructorsRemainFunctional() {
        // Three-arg (primary autowired) ctor must still compile and be callable
        JwtService svc = realJwtService();
        // 1-arg ctor
        JwtAuthenticationFilter f1 = new JwtAuthenticationFilter(svc);
        assertNotNull(f1);
        // 2-arg ctor
        io.castellum.audit.AuditService audit = mock(io.castellum.audit.AuditService.class);
        JwtAuthenticationFilter f2 = new JwtAuthenticationFilter(svc, audit);
        assertNotNull(f2);
        // 3-arg ctor (primary)
        UserRepository repo = mock(UserRepository.class);
        JwtAuthenticationFilter f3 = new JwtAuthenticationFilter(svc, audit, repo);
        assertNotNull(f3);
    }
}

package io.castellum.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private static final String TEST_SECRET = "test-secret-test-secret-test-secret-1234";

    private JwtService service(String secret, long ttl) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("test");
        return new JwtService(secret, ttl, env);
    }

    private JwtService defaultService() {
        return service(TEST_SECRET, 3600);
    }

    @Test
    void issuesAndVerifiesRoundTrip() {
        JwtService svc = defaultService();
        String token = svc.issueToken("alice", List.of("ADMIN"));
        assertEquals("alice", svc.extractUsername(token));
        assertTrue(svc.extractRoles(token).contains("ADMIN"));
    }

    @Test
    void expiredTokenRejected() throws InterruptedException {
        JwtService svc = service(TEST_SECRET, 0);
        // Issue with ttl=0 to get immediate expiry, then wait briefly
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("test");
        // Use ttl=1 second and wait 1500ms
        JwtService shortLived = service(TEST_SECRET, 1);
        String token = shortLived.issueToken("alice", List.of("ADMIN"));
        Thread.sleep(1500);
        assertThrows(ExpiredJwtException.class, () -> shortLived.parse(token));
    }

    @Test
    void tamperedSignatureRejected() {
        JwtService svc = defaultService();
        String token = svc.issueToken("alice", List.of("ADMIN"));
        // Replace last 5 chars of the token with AAAAA
        String tampered = token.substring(0, token.length() - 5) + "AAAAA";
        assertThrows(SignatureException.class, () -> svc.parse(tampered));
    }

    @Test
    void missingRolesClaimReturnsEmpty() {
        JwtService svc = defaultService();
        // Build a token without roles claim using the same key
        String token = Jwts.builder()
                .subject("x")
                .issuer("castellum")
                .signWith(svc.key())
                .compact();
        List<String> roles = svc.extractRoles(token);
        assertTrue(roles.isEmpty(), "missing roles claim should yield empty list");
    }

    @Test
    void shortSecretRejected() {
        assertThrows(IllegalStateException.class, () -> service("short", 3600));
    }

    @Test
    void defaultPlaceholderRejectedOutsideTestProfile() {
        MockEnvironment env = new MockEnvironment();
        // no active profiles — not "test"
        assertThrows(IllegalStateException.class,
            () -> new JwtService(JwtService.DEFAULT_PLACEHOLDER, 3600, env));
    }
}

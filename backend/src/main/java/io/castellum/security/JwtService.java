package io.castellum.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Service
public class JwtService {

    static final String DEFAULT_PLACEHOLDER = "change-me-please-generate-a-32-plus-byte-secret";
    static final String ISSUER = "castellum";

    private final SecretKey key;
    private final long ttlSeconds;

    public JwtService(
            @Value("${castellum.security.jwt.secret}") String secret,
            @Value("${castellum.security.jwt.ttl-seconds:3600}") long ttlSeconds,
            Environment env) {
        boolean testProfile = Arrays.asList(env.getActiveProfiles()).contains("test");
        if (DEFAULT_PLACEHOLDER.equals(secret) && !testProfile) {
            throw new IllegalStateException(
                "Refusing to start with default JWT secret placeholder; set CASTELLUM_SECURITY_JWT_SECRET");
        }
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalStateException(
                "castellum.security.jwt.secret must be >= 32 bytes; got " + bytes.length);
        }
        this.key = Keys.hmacShaKeyFor(bytes);
        this.ttlSeconds = ttlSeconds;
    }

    public String issueToken(String username, List<String> roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuer(ISSUER)
                .issuedAt(java.util.Date.from(now))
                .expiration(java.util.Date.from(now.plusSeconds(ttlSeconds)))
                .signWith(key)
                .compact();
    }

    public Jws<Claims> parse(String token) {
        return Jwts.parser().verifyWith(key).requireIssuer(ISSUER).build().parseSignedClaims(token);
    }

    public String extractUsername(String token) {
        return parse(token).getPayload().getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Object raw = parse(token).getPayload().get("roles");
        if (raw instanceof List<?> list) {
            return list.stream().map(Object::toString).toList();
        }
        return Collections.emptyList();
    }

    public long ttlSeconds() { return ttlSeconds; }

    /** Package-private: exposes key for test-only JWT construction. */
    SecretKey key() { return key; }
}

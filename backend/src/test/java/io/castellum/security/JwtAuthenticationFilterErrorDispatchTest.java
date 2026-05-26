package io.castellum.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.security.Role;
import io.castellum.security.User;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the ERROR-dispatch interception bug is fixed using a real embedded server
 * (RANDOM_PORT). MockMvc does not trigger servlet ERROR dispatch; only a real HTTP request
 * through Tomcat exercises the actual DispatcherServlet error-forwarding path.
 *
 * <p>Root cause: when an authenticated request reaches a controller that throws
 * (e.g. MissingServletRequestParameterException → 400), Spring forwards to {@code /error}
 * with {@code DispatcherType.ERROR}. The Spring Security filter chain re-ran on that forward;
 * the JWT filter found no {@code Authorization} header (not present in forwarded context)
 * and the authorization layer emitted 401, masking the real 400/404.
 *
 * <p>Fix: {@code JwtAuthenticationFilter.shouldNotFilter} returns {@code true} for ERROR-dispatch,
 * and {@code SecurityConfig} adds {@code /error} to {@code permitAll()}.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class JwtAuthenticationFilterErrorDispatchTest {

    @LocalServerPort int port;

    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired ObjectMapper objectMapper;
    @Autowired TestRestTemplate restTemplate;

    private String adminJwt;

    @BeforeEach
    void seed() throws Exception {
        userRepository.deleteAll();
        userRepository.save(new User("edisp_admin", passwordEncoder.encode("pw"),
                Role.ADMIN, true, Instant.now()));
        adminJwt = obtainJwt("edisp_admin", "pw");
    }

    private String obtainJwt(String username, String password) throws Exception {
        String body = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/json");
        ResponseEntity<String> resp = restTemplate.exchange(
                "http://localhost:" + port + "/api/auth/login",
                HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
        JsonNode node = objectMapper.readTree(resp.getBody());
        return node.get("token").asText();
    }

    /**
     * Test 1: GET /api/cve (no ?cpe param, no Authorization) → expect 401 with path=/api/cve.
     * Confirms the 401 is the correct "not authenticated" response from the original resource,
     * NOT a masked 401 emitted by a secondary /error re-dispatch (which would show path=/error).
     */
    @Test
    void missingCpeParam_noToken_returns401WithCorrectPath() throws Exception {
        ResponseEntity<String> resp = restTemplate.getForEntity(
                "http://localhost:" + port + "/api/cve", String.class);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        JsonNode body = objectMapper.readTree(resp.getBody());
        // The path must be the original endpoint, not /error
        assertThat(body.path("path").asText()).isEqualTo("/api/cve");
    }

    /**
     * Test 2: GET /api/cve (no ?cpe param, WITH valid admin Bearer token) → expect 400.
     * Without the fix: Spring forwards to /error after MissingServletRequestParameterException;
     * the JWT filter re-runs on the ERROR forward, the auth context is lost (no Authorization
     * header in the forwarded request), and the authorization layer emits 401 masking the 400.
     */
    @Test
    void missingCpeParam_withAdminToken_returns400Not401() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + adminJwt);
        ResponseEntity<String> resp = restTemplate.exchange(
                "http://localhost:" + port + "/api/cve",
                HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    /**
     * Test 3: GET /nonexistent-endpoint (WITH valid admin Bearer token) → expect 404.
     * Without the fix: Spring forwards to /error after no handler is found;
     * the JWT filter re-runs on the ERROR forward, loses auth context, and
     * the authorization layer emits 401, masking the 404.
     */
    @Test
    void unknownEndpoint_withAdminToken_returns404Not401() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + adminJwt);
        ResponseEntity<String> resp = restTemplate.exchange(
                "http://localhost:" + port + "/nonexistent-endpoint-abc123",
                HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}

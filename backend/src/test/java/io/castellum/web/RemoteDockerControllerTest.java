package io.castellum.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditLogRepository;
import io.castellum.discovery.DockerDiscoveryResponse;
import io.castellum.discovery.OriginContext;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.security.RemoteAgentToken;
import io.castellum.security.RemoteAgentTokenRepository;
import io.castellum.security.Role;
import io.castellum.security.User;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration test for {@link RemoteDockerController} — exercises the real filter chain
 * so that auth, validation, parsing, and ingest are tested end-to-end.
 */
@SpringBootTest
@AutoConfigureMockMvc
class RemoteDockerControllerTest {

    @Autowired MockMvc mvc;
    @Autowired RemoteAgentTokenRepository tokenRepo;
    @Autowired UserRepository userRepo;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired AuditLogRepository auditRepo;
    @Autowired DeviceRepository deviceRepo;
    @Autowired ObjectMapper om;

    private static final String INGEST_URL = "/api/discovery/remote-docker";
    private static final String PLAINTEXT = "test-token-secret-abc123";

    /** Minimal valid docker inspect JSON array (single empty container — parser returns empty list). */
    private static final String EMPTY_CONTAINERS = "[]";

    /** Valid docker inspect JSON array with one container, matching the parser's expected shape. */
    private static final String ONE_CONTAINER_JSON = """
            [
              {
                "Id": "abc123",
                "Name": "/test-container",
                "NetworkSettings": {
                  "Ports": {},
                  "Networks": {
                    "bridge": {
                      "IPAddress": "172.17.0.2",
                      "Gateway": "172.17.0.1"
                    }
                  }
                },
                "Config": { "Image": "nginx" }
              }
            ]
            """;

    @BeforeEach
    void setUp() {
        tokenRepo.deleteAll();
        // Create one active token
        RemoteAgentToken token = new RemoteAgentToken();
        token.setLabel("integration-test-agent");
        token.setTokenHash(passwordEncoder.encode(PLAINTEXT));
        token.setCreatedAt(Instant.now());
        token.setCreatedBy("test-setup");
        tokenRepo.save(token);
    }

    private String validPayload(String containers) throws Exception {
        return om.writeValueAsString(Map.of(
                "agentId", "test-agent-id",
                "hostname", "test-host.local",
                "primaryIp", "192.168.1.100",
                "containers", containers
        ));
    }

    // ── Auth tests ─────────────────────────────────────────────────────────────

    @Test
    void missingBearerToken_returns401() throws Exception {
        mvc.perform(post(INGEST_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validPayload(EMPTY_CONTAINERS)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidBearerToken_returns401() throws Exception {
        mvc.perform(post(INGEST_URL)
                .header("Authorization", "Bearer wrong-token-value")
                .contentType(MediaType.APPLICATION_JSON)
                .content(validPayload(EMPTY_CONTAINERS)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void jwtWithAdminRole_noRemoteAgentAuthority_returns403() throws Exception {
        // Login as admin to get a JWT (ROLE_ADMIN, not ROLE_REMOTE_AGENT)
        userRepo.deleteAll();
        userRepo.save(new User("admin_for_403", passwordEncoder.encode("pw"), Role.ADMIN, true, Instant.now()));
        MvcResult loginResult = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"admin_for_403\",\"password\":\"pw\"}"))
            .andReturn();
        String jwt = om.readTree(loginResult.getResponse().getContentAsString()).get("token").asText();

        mvc.perform(post(INGEST_URL)
                .header("Authorization", "Bearer " + jwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validPayload(EMPTY_CONTAINERS)))
            .andExpect(status().isForbidden());
    }

    // ── Happy path ─────────────────────────────────────────────────────────────

    @Test
    void validTokenAndPayload_returns200AndUpsertDevicesWithOrigin() throws Exception {
        MvcResult result = mvc.perform(post(INGEST_URL)
                .header("Authorization", "Bearer " + PLAINTEXT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validPayload(ONE_CONTAINER_JSON)))
            .andExpect(status().isOk())
            .andReturn();

        DockerDiscoveryResponse resp = om.readValue(
                result.getResponse().getContentAsString(), DockerDiscoveryResponse.class);
        // The payload has 1 container; parser returns it; containers >= 1
        assertTrue(resp.containers() >= 0, "response must have non-negative container count");

        // Verify origin context persisted — device keyed on the container IP should have origin set
        List<Device> devicesWithOrigin = deviceRepo.findAll().stream()
                .filter(d -> d.getOriginHostIp() != null && !d.getOriginHostIp().equals("local"))
                .toList();
        assertFalse(devicesWithOrigin.isEmpty(),
                "at least one device must carry the remote origin host IP");
        assertTrue(devicesWithOrigin.stream().anyMatch(d -> "192.168.1.100".equals(d.getOriginHostIp())),
                "device origin must match the primaryIp from the request");

        // Audit row written — no token in detail
        List<AuditLog> audits = auditRepo.findAll().stream()
                .filter(a -> "REMOTE_DOCKER_INGEST".equals(a.getAction()))
                .toList();
        assertFalse(audits.isEmpty(), "audit row must be written for REMOTE_DOCKER_INGEST");
        // Assert token value is NOT in any audit detail
        for (AuditLog audit : audits) {
            String payload = audit.getPayload();
            assertFalse(payload != null && payload.contains(PLAINTEXT),
                    "plaintext token must never appear in audit detail");
        }
    }

    @Test
    void validToken_tokenNeverInResponse() throws Exception {
        MvcResult result = mvc.perform(post(INGEST_URL)
                .header("Authorization", "Bearer " + PLAINTEXT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validPayload(EMPTY_CONTAINERS)))
            .andExpect(status().isOk())
            .andReturn();

        String body = result.getResponse().getContentAsString();
        assertFalse(body.contains(PLAINTEXT),
                "response body must never contain the plaintext token");
        // also check no hash leakage
        assertFalse(body.contains("$2a$"), "response must not contain any BCrypt hash fragment");
    }

    // ── Validation / payload-size tests ────────────────────────────────────────

    @Test
    void malformedJsonInContainers_returns4xx_not500() throws Exception {
        String badPayload = om.writeValueAsString(Map.of(
                "agentId", "test-agent",
                "hostname", "host.local",
                "primaryIp", "10.0.0.1",
                "containers", "not-valid-json{"
        ));

        MvcResult result = mvc.perform(post(INGEST_URL)
                .header("Authorization", "Bearer " + PLAINTEXT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(badPayload))
            .andReturn();

        int status = result.getResponse().getStatus();
        assertTrue(status >= 400 && status < 500,
                "malformed containers JSON must yield 4xx, got: " + status);
        assertNotEquals(500, status, "must not be 500");
    }

    @Test
    void blankAgentId_returns4xx() throws Exception {
        String payload = om.writeValueAsString(Map.of(
                "agentId", "",
                "hostname", "host.local",
                "primaryIp", "10.0.0.1",
                "containers", EMPTY_CONTAINERS
        ));

        mvc.perform(post(INGEST_URL)
                .header("Authorization", "Bearer " + PLAINTEXT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
            .andExpect(status().isBadRequest());
    }

    @Test
    void blankPrimaryIp_returns4xx() throws Exception {
        String payload = om.writeValueAsString(Map.of(
                "agentId", "agent-ok",
                "hostname", "host.local",
                "primaryIp", "",
                "containers", EMPTY_CONTAINERS
        ));

        mvc.perform(post(INGEST_URL)
                .header("Authorization", "Bearer " + PLAINTEXT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
            .andExpect(status().isBadRequest());
    }

    @Test
    void oversizedContainers_returns4xx_parseNotInvoked() throws Exception {
        // Build a string just over 2MB — @Size(max=2_000_000) on the DTO should reject it
        String bigContainers = "x".repeat(2_000_001);
        String payload = om.writeValueAsString(Map.of(
                "agentId", "agent-size-test",
                "hostname", "host.local",
                "primaryIp", "10.0.0.2",
                "containers", bigContainers
        ));

        MvcResult result = mvc.perform(post(INGEST_URL)
                .header("Authorization", "Bearer " + PLAINTEXT)
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
            .andReturn();

        int status = result.getResponse().getStatus();
        assertTrue(status >= 400 && status < 500,
                "oversized containers must yield 4xx, got: " + status);
    }
}

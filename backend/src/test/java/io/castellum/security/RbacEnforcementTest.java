package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class RbacEnforcementTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder enc;
    @Autowired AuditLogRepository auditRepo;
    @Autowired ObjectMapper om;

    private String adminJwt;
    private String viewerJwt;

    @BeforeEach
    void seed() throws Exception {
        users.deleteAll();
        users.save(new User("rbac_admin", enc.encode("pw"), Role.ADMIN, true, Instant.now()));
        users.save(new User("rbac_viewer", enc.encode("pw"), Role.VIEWER, true, Instant.now()));
        adminJwt = obtainJwt("rbac_admin", "pw");
        viewerJwt = obtainJwt("rbac_viewer", "pw");
    }

    private String obtainJwt(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
            .andReturn();
        return om.readTree(result.getResponse().getContentAsString()).get("token").asText();
    }

    /**
     * Matrix: method, path, requiredRole ("ADMIN" = mutating, "VIEWER+" = read-only), expectedStatus
     * expectedStatus is the status admin should get (may be 400 if body is required but we pass {})
     */
    static Stream<Arguments> matrix() {
        // expectedStatus = status admin receives (may be non-2xx if body triggers further validation,
        // but must never be 401 or 403 — the test's pass condition is: status != 401 && status != 403)
        return Stream.of(
            Arguments.of("GET",  "/api/devices",             "VIEWER+", 200),
            Arguments.of("POST", "/api/devices",             "ADMIN",   201),
            Arguments.of("GET",  "/api/services",            "VIEWER+", 200),
            Arguments.of("POST", "/api/services",            "ADMIN",   201),
            Arguments.of("POST", "/api/scan",                "ADMIN",   202),
            Arguments.of("GET",  "/api/scans",               "VIEWER+", 200),
            Arguments.of("GET",  "/api/cve",                 "VIEWER+", 200),
            Arguments.of("GET",  "/api/risk/score",          "VIEWER+", 400),
            Arguments.of("GET",  "/api/risk/feeds/status",   "VIEWER+", 200),
            Arguments.of("POST", "/api/discovery/passive",   "ADMIN",   200),
            Arguments.of("POST", "/api/ot-probe",            "ADMIN",   502), // no real device
            Arguments.of("GET",  "/api/graph/shortest-path", "VIEWER+", 400)
        );
    }

    @ParameterizedTest(name = "anon→401: {0} {1}")
    @MethodSource("matrix")
    void anon_returns_401(String method, String path, String role, int ignored) throws Exception {
        var req = buildRequest(method, path);
        mvc.perform(req).andExpect(status().isUnauthorized());
    }

    @ParameterizedTest(name = "viewer on mutating→403: {0} {1}")
    @MethodSource("matrix")
    void viewer_on_mutating_returns_403(String method, String path, String role, int ignored) throws Exception {
        if (!"ADMIN".equals(role)) return; // skip read-only rows
        int before = auditRepo.findAll().size();

        var req = buildRequest(method, path)
            .header("Authorization", "Bearer " + viewerJwt);
        mvc.perform(req).andExpect(status().isForbidden());

        boolean rbacDeny = auditRepo.findAll().stream()
            .skip(before)
            .anyMatch(r -> "RBAC_DENY".equals(r.getAction()) && r.getResourceId() != null && r.getResourceId().contains(path));
        assertTrue(rbacDeny, "RBAC_DENY audit row expected for viewer on " + method + " " + path);
    }

    @ParameterizedTest(name = "admin succeeds: {0} {1}")
    @MethodSource("matrix")
    void admin_succeeds(String method, String path, String role, int expectedStatus) throws Exception {
        var req = buildRequest(method, path)
            .header("Authorization", "Bearer " + adminJwt);
        MvcResult result = mvc.perform(req).andReturn();
        int status = result.getResponse().getStatus();
        // Must not be 401 or 403 — RBAC passed
        assertTrue(status != 401 && status != 403,
            "Admin should pass RBAC on " + method + " " + path + " but got " + status);
    }

    /** Minimal valid bodies that pass @Valid so RBAC is the sole differentiator. */
    private static final java.util.Map<String, String> VALID_BODIES = java.util.Map.of(
        "/api/devices",           "{\"ipAddress\":\"10.0.0.1\"}",
        "/api/services",          "{\"deviceId\":1,\"port\":80,\"protocol\":\"tcp\"}",
        "/api/scan",              "{\"cidr\":\"10.0.0.0/24\",\"type\":\"PING_SWEEP\"}",
        "/api/discovery/passive", "{\"iface\":\"eth0\",\"durationSeconds\":10,\"sources\":[\"ARP\"]}",
        "/api/ot-probe",          "{\"host\":\"10.0.0.1\",\"port\":502,\"protocol\":\"MODBUS_TCP\"}"
    );

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder buildRequest(
            String method, String path) {
        String body = VALID_BODIES.getOrDefault(path, "{}");
        var builder = switch (method.toUpperCase()) {
            case "GET"    -> get(path);
            case "POST"   -> post(path).contentType(MediaType.APPLICATION_JSON).content(body);
            case "PUT"    -> put(path).contentType(MediaType.APPLICATION_JSON).content(body);
            case "DELETE" -> delete(path);
            default       -> throw new IllegalArgumentException("Unknown method: " + method);
        };
        return builder;
    }
}

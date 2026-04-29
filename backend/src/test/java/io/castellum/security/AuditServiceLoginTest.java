package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditLogRepository;
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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuditServiceLoginTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired AuditLogRepository auditLogRepository;
    @Autowired ObjectMapper objectMapper;

    @BeforeEach
    void seed() {
        userRepository.deleteAll();
        User admin = new User("audmin", passwordEncoder.encode("pw"), Role.ADMIN, true, Instant.now());
        userRepository.save(admin);
        User viewer = new User("audviewer", passwordEncoder.encode("pw"), Role.VIEWER, true, Instant.now());
        userRepository.save(viewer);
    }

    private String loginAndExtractToken(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
            .andReturn();
        String body = result.getResponse().getContentAsString();
        return objectMapper.readTree(body).get("token").asText();
    }

    @Test
    void loginSuccessAuditWritten() throws Exception {
        int before = auditLogRepository.findAll().size();
        loginAndExtractToken("audmin", "pw");
        boolean found = auditLogRepository.findAll().stream()
            .skip(before)
            .anyMatch(r -> "LOGIN_SUCCESS".equals(r.getAction()) && "audmin".equals(r.getActor()));
        assertTrue(found, "LOGIN_SUCCESS audit row must be written");
    }

    @Test
    void loginFailAuditWritten() throws Exception {
        int before = auditLogRepository.findAll().size();
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"audmin\",\"password\":\"wrong\"}"))
            .andExpect(status().isUnauthorized());
        boolean found = auditLogRepository.findAll().stream()
            .skip(before)
            .anyMatch(r -> "LOGIN_FAIL".equals(r.getAction()) && "audmin".equals(r.getActor()));
        assertTrue(found, "LOGIN_FAIL audit row must be written");
    }

    @Test
    void rbacDenyAuditWritten() throws Exception {
        String viewerToken = loginAndExtractToken("audviewer", "pw");
        int before = auditLogRepository.findAll().size();
        mvc.perform(post("/api/devices")
                .header("Authorization", "Bearer " + viewerToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"10.0.0.99\",\"firstSeen\":\"2024-01-01T00:00:00Z\",\"lastSeen\":\"2024-01-01T00:00:00Z\"}"))
            .andExpect(status().isForbidden());
        boolean found = auditLogRepository.findAll().stream()
            .skip(before)
            .anyMatch(r -> "RBAC_DENY".equals(r.getAction())
                && r.getResourceId() != null && r.getResourceId().contains("/api/devices"));
        assertTrue(found, "RBAC_DENY audit row must be written for viewer POST /api/devices");
    }
}

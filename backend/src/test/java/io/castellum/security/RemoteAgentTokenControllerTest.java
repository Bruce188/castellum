package io.castellum.security;

import com.fasterxml.jackson.databind.JsonNode;
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
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class RemoteAgentTokenControllerTest {

    @Autowired MockMvc mvc;
    @Autowired RemoteAgentTokenRepository tokenRepo;
    @Autowired AuditLogRepository auditRepo;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired ObjectMapper om;

    private static final String BASE_URL = "/api/discovery/remote-docker/tokens";

    @BeforeEach
    void setUp() {
        tokenRepo.deleteAll();
    }

    // ── Create ─────────────────────────────────────────────────────────────────

    @Test
    @WithMockUser(username = "test-admin", roles = "ADMIN")
    void create_returns201WithPlaintextToken() throws Exception {
        MvcResult result = mvc.perform(post(BASE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"label\":\"my-agent\"}"))
            .andExpect(status().isCreated())
            .andReturn();

        JsonNode body = om.readTree(result.getResponse().getContentAsString());
        String token = body.get("token").asText();
        assertNotNull(token, "response must include plaintext token");
        assertFalse(token.isBlank(), "token must not be blank");

        // Verify stored hash != plaintext and BCrypt.matches
        List<RemoteAgentToken> all = tokenRepo.findAll();
        assertEquals(1, all.size());
        String storedHash = all.get(0).getTokenHash();
        assertNotEquals(token, storedHash, "stored hash must not equal plaintext");
        assertTrue(passwordEncoder.matches(token, storedHash),
            "passwordEncoder.matches(plaintext, storedHash) must be true");
    }

    @Test
    @WithMockUser(username = "audit-test-admin", roles = "ADMIN")
    void create_auditRowWritten_noTokenValueInDetail() throws Exception {
        mvc.perform(post(BASE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"label\":\"audit-test-agent\"}"))
            .andExpect(status().isCreated());

        // Filter by actor and action for isolation
        List<AuditLog> audits = auditRepo.findByActor("audit-test-admin").stream()
            .filter(a -> "REMOTE_AGENT_TOKEN_CREATE".equals(a.getAction()))
            .toList();
        assertFalse(audits.isEmpty(), "audit row must be written on create");

        // Assert audit payload doesn't contain any BCrypt marker
        for (AuditLog audit : audits) {
            String payload = audit.getPayload();
            assertFalse(payload != null && payload.contains("$2a$"),
                "audit must not contain BCrypt hash");
            // payload should contain the label
            assertTrue(payload != null && payload.contains("audit-test-agent"),
                "audit must include the label; got: " + payload);
        }
    }

    @Test
    @WithMockUser(username = "test-admin", roles = "ADMIN")
    void list_returnsMetadataOnly_noTokenHashOrPlaintext() throws Exception {
        // First create a token
        MvcResult createResult = mvc.perform(post(BASE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"label\":\"list-test-agent\"}"))
            .andExpect(status().isCreated())
            .andReturn();

        String createdToken = om.readTree(createResult.getResponse().getContentAsString())
            .get("token").asText();

        // Now list
        MvcResult listResult = mvc.perform(get(BASE_URL))
            .andExpect(status().isOk())
            .andReturn();

        String listBody = listResult.getResponse().getContentAsString();
        // token value must NOT appear in list
        assertFalse(listBody.contains(createdToken),
            "plaintext token must not appear in list response");
        // tokenHash must not appear
        assertFalse(listBody.contains("$2a$"),
            "BCrypt hash must not appear in list response");
        assertFalse(listBody.contains("tokenHash"),
            "tokenHash field must not be serialized in list response");
        // token field must not appear (only in create response)
        assertFalse(listBody.contains("\"token\""),
            "token field must not appear in list response");
        // label must be present
        assertTrue(listBody.contains("list-test-agent"), "label must appear in list");
    }

    @Test
    @WithMockUser(username = "test-admin", roles = "ADMIN")
    void revoke_returns204AndSetsRevokedFields() throws Exception {
        // Create first
        MvcResult createResult = mvc.perform(post(BASE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"label\":\"revoke-test-agent\"}"))
            .andExpect(status().isCreated())
            .andReturn();

        Long id = om.readTree(createResult.getResponse().getContentAsString()).get("id").asLong();

        // Revoke
        mvc.perform(post(BASE_URL + "/" + id + "/revoke"))
            .andExpect(status().isNoContent());

        // Verify in DB
        RemoteAgentToken t = tokenRepo.findById(id).orElseThrow();
        assertTrue(t.isRevoked(), "revoked must be true after revoke");
        assertNotNull(t.getRevokedAt(), "revokedAt must be set after revoke");

        // Audit row for revoke
        List<AuditLog> revokeAudits = auditRepo.findAll().stream()
            .filter(a -> "REMOTE_AGENT_TOKEN_REVOKE".equals(a.getAction()))
            .toList();
        assertFalse(revokeAudits.isEmpty(), "audit row must be written on revoke");
    }

    @Test
    @WithMockUser(username = "test-viewer", roles = "VIEWER")
    void nonAdmin_returns403() throws Exception {
        mvc.perform(post(BASE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"label\":\"should-fail\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "test-admin", roles = "ADMIN")
    void create_blankLabel_returns4xx() throws Exception {
        mvc.perform(post(BASE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"label\":\"\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "test-admin", roles = "ADMIN")
    void create_oversizedLabel_returns4xx() throws Exception {
        String bigLabel = "a".repeat(129); // > 128
        mvc.perform(post(BASE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"label\":\"" + bigLabel + "\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "test-admin", roles = "ADMIN")
    void plaintextShownOnce_listAndRevokeNeverReturnIt() throws Exception {
        // Create
        MvcResult createResult = mvc.perform(post(BASE_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"label\":\"once-test-agent\"}"))
            .andExpect(status().isCreated())
            .andReturn();

        String plaintext = om.readTree(createResult.getResponse().getContentAsString())
            .get("token").asText();
        Long id = om.readTree(createResult.getResponse().getContentAsString()).get("id").asLong();

        // List must not contain plaintext
        MvcResult listResult = mvc.perform(get(BASE_URL)).andReturn();
        assertFalse(listResult.getResponse().getContentAsString().contains(plaintext),
            "list must not return plaintext token");

        // Revoke must not return plaintext
        MvcResult revokeResult = mvc.perform(post(BASE_URL + "/" + id + "/revoke")).andReturn();
        assertFalse(revokeResult.getResponse().getContentAsString().contains(plaintext),
            "revoke must not return plaintext token");
    }
}

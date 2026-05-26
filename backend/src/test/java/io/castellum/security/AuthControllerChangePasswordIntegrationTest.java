package io.castellum.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * End-to-end behaviour of the change-password flow against a live Spring context
 * (H2 datasource). Exercises: login, password change with the issued JWT,
 * token-version invalidation, login with new password succeeds, login with old
 * password fails, rate-limit returns 429.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerChangePasswordIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder encoder;
    @Autowired PasswordChangeRateLimiter passwordChangeRateLimiter;

    private static final String USERNAME = "pwchange-user";
    private static final String OLD_PASSWORD = "oldpassword1!";
    private static final String NEW_PASSWORD = "newpassword2@";

    @BeforeEach
    void setup() {
        userRepository.findByUsername(USERNAME).ifPresent(userRepository::delete);
        User u = new User(USERNAME, encoder.encode(OLD_PASSWORD), Role.VIEWER, true, Instant.now());
        userRepository.save(u);
        // clear any leaked rate-limit state from siblings
        passwordChangeRateLimiter.attempts().remove(USERNAME);
    }

    @AfterEach
    void teardown() {
        userRepository.findByUsername(USERNAME).ifPresent(userRepository::delete);
        passwordChangeRateLimiter.attempts().remove(USERNAME);
    }

    private String login(String username, String password) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(om.writeValueAsString(java.util.Map.of(
                    "username", username, "password", password))))
            .andExpect(status().isOk())
            .andReturn();
        JsonNode body = om.readTree(res.getResponse().getContentAsString());
        return body.get("token").asText();
    }

    @Test
    void happyPath_changePassword_then_loginWithNewSucceeds_andOldFails() throws Exception {
        String token = login(USERNAME, OLD_PASSWORD);

        mvc.perform(post("/api/auth/change-password")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"" + OLD_PASSWORD + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}"))
            .andExpect(status().isNoContent());

        // Old password — fail
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(om.writeValueAsString(java.util.Map.of(
                    "username", USERNAME, "password", OLD_PASSWORD))))
            .andExpect(status().isUnauthorized());

        // New password — succeed
        String fresh = login(USERNAME, NEW_PASSWORD);
        assertNotNull(fresh);
        assertNotEquals(token, fresh);
    }

    @Test
    void oldTokenIsRejected_afterPasswordChange_tokenVersionBumped() throws Exception {
        String token = login(USERNAME, OLD_PASSWORD);
        int versionBefore = userRepository.findByUsername(USERNAME).orElseThrow().getTokenVersion();

        mvc.perform(post("/api/auth/change-password")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"" + OLD_PASSWORD + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}"))
            .andExpect(status().isNoContent());

        int versionAfter = userRepository.findByUsername(USERNAME).orElseThrow().getTokenVersion();
        assertEquals(versionBefore + 1, versionAfter,
            "tokenVersion must be bumped on successful password change");

        // Original JWT now has a stale tv claim — must be rejected on the next request.
        mvc.perform(get("/api/devices")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongOldPassword_returns401_andDoesNotPersist() throws Exception {
        String token = login(USERNAME, OLD_PASSWORD);
        String originalHash = userRepository.findByUsername(USERNAME).orElseThrow().getPasswordHash();

        mvc.perform(post("/api/auth/change-password")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"wrong-old\",\"newPassword\":\"" + NEW_PASSWORD + "\"}"))
            .andExpect(status().isUnauthorized());

        String laterHash = userRepository.findByUsername(USERNAME).orElseThrow().getPasswordHash();
        assertEquals(originalHash, laterHash, "passwordHash must be unchanged on failure");
    }

    @Test
    void fourthAttemptInWindow_returns429() throws Exception {
        String token = login(USERNAME, OLD_PASSWORD);
        // First three wrong-password attempts spend budget (all 401)
        for (int i = 0; i < 3; i++) {
            mvc.perform(post("/api/auth/change-password")
                    .header("Authorization", "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"oldPassword\":\"wrong-old\",\"newPassword\":\"" + NEW_PASSWORD + "\"}"))
                .andExpect(status().isUnauthorized());
        }
        // Fourth attempt — over budget → 429
        mvc.perform(post("/api/auth/change-password")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"oldPassword\":\"" + OLD_PASSWORD + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}"))
            .andExpect(status().is(429))
            .andExpect(header().exists("Retry-After"));
    }
}

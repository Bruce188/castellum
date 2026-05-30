package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.config.CorsConfig;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
class SecurityConfigIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired ObjectMapper objectMapper;

    @BeforeEach
    void seed() {
        userRepository.deleteAll();
        userRepository.save(new User("scadmin", passwordEncoder.encode("pw"), Role.ADMIN, true, Instant.now()));
        userRepository.save(new User("scviewer", passwordEncoder.encode("pw"), Role.VIEWER, true, Instant.now()));
    }

    private String obtainJwt(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
            .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    void anonOnApiDevicesReturns401() throws Exception {
        mvc.perform(get("/api/devices")).andExpect(status().isUnauthorized());
    }

    @Test
    void anonOnApiServicesReturns401() throws Exception {
        mvc.perform(get("/api/services")).andExpect(status().isUnauthorized());
    }

    @Test
    void anonOnApiCveReturns401() throws Exception {
        mvc.perform(get("/api/cve")).andExpect(status().isUnauthorized());
    }

    @Test
    void anonOnApiRiskScoreReturns401() throws Exception {
        mvc.perform(get("/api/risk/score")).andExpect(status().isUnauthorized());
    }

    @Test
    void viewerCanGetDevicesReturns200() throws Exception {
        String jwt = obtainJwt("scviewer", "pw");
        mvc.perform(get("/api/devices").header("Authorization", "Bearer " + jwt))
            .andExpect(status().isOk());
    }

    @Test
    void viewerCannotPostDevicesReturns403() throws Exception {
        String jwt = obtainJwt("scviewer", "pw");
        mvc.perform(post("/api/devices")
                .header("Authorization", "Bearer " + jwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"10.0.0.88\",\"firstSeen\":\"2024-01-01T00:00:00Z\",\"lastSeen\":\"2024-01-01T00:00:00Z\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void adminCanPostDevicesReturns2xx() throws Exception {
        String jwt = obtainJwt("scadmin", "pw");
        mvc.perform(post("/api/devices")
                .header("Authorization", "Bearer " + jwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ipAddress\":\"10.0.0.77\",\"firstSeen\":\"2024-01-01T00:00:00Z\",\"lastSeen\":\"2024-01-01T00:00:00Z\"}"))
            .andExpect(status().is2xxSuccessful());
    }

    @Test
    void permitAllOnHealthAndLoginReturnsExpected() throws Exception {
        // Actuator health — no JWT → 200
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
        // Login with empty body → 400 (validation fired before any security rejection)
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void actuatorHealthAnonymousResponseHasNoComponents() throws Exception {
        mvc.perform(get("/actuator/health"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("UP"))
            .andExpect(jsonPath("$.components").doesNotExist());
    }

    @Test
    void apiResponseHasSecurityHeaders() throws Exception {
        // CSP and X-Frame-Options are emitted on every response; HSTS is emitted only on
        // HTTPS-origin requests — here simulated via the proxy-forwarded X-Forwarded-Proto.
        mvc.perform(get("/api/devices").header("X-Forwarded-Proto", "https"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().exists("Content-Security-Policy"))
            .andExpect(header().exists("Strict-Transport-Security"))
            .andExpect(header().exists("X-Frame-Options"));
    }

    @Test
    void plainHttpResponseOmitsHsts() throws Exception {
        // Regression guard: HSTS must NOT be sent on plain-HTTP requests (RFC 6797 §7.2) —
        // forcing it pins a stale https upgrade on local-dev hosts. CSP and X-Frame-Options
        // remain present unconditionally.
        mvc.perform(get("/api/devices"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().exists("Content-Security-Policy"))
            .andExpect(header().exists("X-Frame-Options"))
            .andExpect(header().doesNotExist("Strict-Transport-Security"));
    }

    @Test
    void malformedCorsOriginFailsContextLoad() {
        ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(CorsConfig.class)
            .withPropertyValues("castellum.cors.allowed-origins=*.example.com");
        runner.run(ctx -> {
            Assertions.assertThat(ctx).hasFailed();
            Assertions.assertThat(ctx.getStartupFailure())
                .hasMessageContaining("CORS wildcard subdomain forbidden");
        });
    }
}

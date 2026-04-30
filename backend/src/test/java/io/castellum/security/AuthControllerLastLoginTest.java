package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerLastLoginTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder encoder;

    @AfterEach
    void cleanup() {
        userRepository.findByUsername("lasttest").ifPresent(userRepository::delete);
    }

    @Test
    void successfulLoginPersistsLastLoginAt() throws Exception {
        User u = new User(
            "lasttest",
            encoder.encode("pwd"),
            Role.ADMIN,
            true,
            Instant.now()
        );
        userRepository.save(u);

        Instant before = Instant.now().minusSeconds(2);

        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                    "username", "lasttest",
                    "password", "pwd"))))
            .andExpect(status().isOk());

        User reloaded = userRepository.findByUsername("lasttest").orElseThrow();
        assertNotNull(reloaded.getLastLoginAt(), "lastLoginAt must be set after login");
        assertTrue(reloaded.getLastLoginAt().isAfter(before),
            "lastLoginAt must be after the pre-login instant");
    }
}

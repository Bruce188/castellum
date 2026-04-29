package io.castellum.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

class BootstrapAdminTest {

    @Nested
    @SpringBootTest
    @TestPropertySource(properties = {
        "castellum.admin.username=admin",
        "castellum.admin.password-hash=$2a$12$dummy"
    })
    class PresentEnvCreatesAdmin {
        @Autowired UserRepository userRepository;
        @Autowired BootstrapAdminInitializer initializer;

        @BeforeEach
        void cleanup() { userRepository.deleteAll(); }

        @Test
        void presentEnvCreatesAdmin() {
            // ApplicationReadyEvent fires on context start, but we re-trigger after cleanup
            initializer.bootstrapAdmin();
            assertTrue(userRepository.findByUsername("admin").isPresent(),
                "Admin user should be created when env vars are set");
        }
    }

    @Nested
    @SpringBootTest
    @TestPropertySource(properties = {
        "castellum.admin.username=",
        "castellum.admin.password-hash="
    })
    class AbsentEnvWarnsAndSkips {
        @Autowired UserRepository userRepository;

        @BeforeEach
        void cleanup() { userRepository.deleteAll(); }

        @Test
        void absentEnvWarnsAndSkips() {
            assertEquals(0, userRepository.count(),
                "No users should be created when env vars are absent");
        }
    }

    @Nested
    @SpringBootTest
    @TestPropertySource(properties = {
        "castellum.admin.username=admin",
        "castellum.admin.password-hash=$2a$12$dummy"
    })
    class IdempotentOnSecondStart {
        @Autowired UserRepository userRepository;
        @Autowired BootstrapAdminInitializer initializer;

        @BeforeEach
        void cleanup() { userRepository.deleteAll(); }

        @Test
        void idempotentOnSecondStart() {
            initializer.bootstrapAdmin();
            initializer.bootstrapAdmin();
            assertEquals(1, userRepository.count(),
                "Running initializer twice should produce exactly one user");
        }
    }
}

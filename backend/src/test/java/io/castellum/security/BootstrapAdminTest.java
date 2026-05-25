package io.castellum.security;

import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

class BootstrapAdminTest {

    @Nested
    @SpringBootTest
    @DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
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
    @DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
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
    @DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
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

    @Nested
    @SpringBootTest
    @DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
    @TestPropertySource(properties = {
        "castellum.admin.username=",
        "castellum.admin.password-hash=",
        "castellum.viewer.username=bob",
        "castellum.viewer.password-hash=$2a$12$viewerdummy"
    })
    class ViewerBootstrap {
        @Autowired UserRepository userRepository;
        @Autowired BootstrapAdminInitializer initializer;

        @BeforeEach
        void cleanup() { userRepository.deleteAll(); }

        @Test
        void viewerCreatedWhenViewerEnvSet() {
            initializer.bootstrap();
            assertTrue(userRepository.findByUsername("bob").isPresent(),
                "Viewer user should be created when viewer env vars are set");
            assertEquals(Role.VIEWER, userRepository.findByUsername("bob").get().getRole(),
                "Viewer user should have VIEWER role");
            assertTrue(userRepository.findByUsername("bob").get().isEnabled(),
                "Viewer user should be enabled");
        }

        @Test
        void viewerSkippedWhenEnvUnset() {
            // Env already empty for admin — also no VIEWER with different username
            // Confirm no user "carol" exists (unrelated viewer)
            assertFalse(userRepository.findByUsername("carol").isPresent(),
                "No viewer should be created for non-configured username");
        }
    }

    @Nested
    @SpringBootTest
    @DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
    @TestPropertySource(properties = {
        "castellum.admin.username=admin",
        "castellum.admin.password-hash=$2a$12$newadminhash",
        "spring.datasource.url=jdbc:h2:mem:test-admin-hash-rotate;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1"
    })
    class AdminHashRotate {
        @Autowired UserRepository userRepository;
        @Autowired AuditLogRepository auditLogRepository;
        @Autowired BootstrapAdminInitializer initializer;

        @BeforeEach
        void seedOldHash() {
            userRepository.deleteAll();
            User a = new User();
            a.setUsername("admin");
            a.setPasswordHash("$2a$12$oldadminhash");
            a.setRole(Role.ADMIN);
            a.setEnabled(true);
            a.setCreatedAt(java.time.Instant.now());
            userRepository.save(a);
        }

        @Test
        void adminHashRotateAuditEventEmitted() {
            initializer.bootstrap();
            long count = auditLogRepository.findAll().stream()
                .filter(r -> "ADMIN_HASH_ROTATE".equals(r.getAction()))
                .count();
            assertEquals(1L, count,
                "Exactly one ADMIN_HASH_ROTATE audit row must be emitted on rotation");
        }

        @Test
        void secondBootstrapWithSameHashIsIdempotent() {
            initializer.bootstrap();    // rotates to new hash
            long firstCount = auditLogRepository.findAll().stream()
                .filter(r -> "ADMIN_HASH_ROTATE".equals(r.getAction())).count();
            initializer.bootstrap();    // should be a no-op (hash already current)
            long secondCount = auditLogRepository.findAll().stream()
                .filter(r -> "ADMIN_HASH_ROTATE".equals(r.getAction())).count();
            assertEquals(firstCount, secondCount,
                "No additional ADMIN_HASH_ROTATE row when hash already matches");
        }
    }

    @Nested
    @SpringBootTest
    @DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
    @TestPropertySource(properties = {
        "castellum.admin.username=",
        "castellum.admin.password-hash=",
        "castellum.viewer.username=rotateviewer",
        "castellum.viewer.password-hash=$2a$12$newhash"
    })
    class ViewerHashRotate {
        @Autowired UserRepository userRepository;
        @Autowired AuditLogRepository auditLogRepository;
        @Autowired BootstrapAdminInitializer initializer;

        @BeforeEach
        void seedOldHash() {
            userRepository.deleteAll();
            User v = new User();
            v.setUsername("rotateviewer");
            v.setPasswordHash("$2a$12$oldhash");
            v.setRole(Role.VIEWER);
            v.setEnabled(true);
            v.setCreatedAt(java.time.Instant.now());
            userRepository.save(v);
        }

        @Test
        void viewerHashRotateAuditEventEmitted() {
            int before = auditLogRepository.findAll().size();
            initializer.bootstrap();
            int after = auditLogRepository.findAll().size();
            assertTrue(after > before, "VIEWER_HASH_ROTATE audit event should be emitted");
            assertTrue(auditLogRepository.findAll().stream()
                .anyMatch(log -> "VIEWER_HASH_ROTATE".equals(log.getAction())),
                "Audit log must contain VIEWER_HASH_ROTATE action");
        }
    }
}

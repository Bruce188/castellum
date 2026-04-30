package io.castellum.security;

import io.castellum.audit.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;

@Component
public class BootstrapAdminInitializer {

    private static final Logger log = LoggerFactory.getLogger(BootstrapAdminInitializer.class);

    private final UserRepository repository;
    private final AuditService auditService;
    private final String adminUsername;
    private final String adminPasswordHash;
    private final String viewerUsername;
    private final String viewerPasswordHash;

    public BootstrapAdminInitializer(
            UserRepository repository,
            AuditService auditService,
            @Value("${castellum.admin.username:#{null}}") String adminUsername,
            @Value("${castellum.admin.password-hash:#{null}}") String adminPasswordHash,
            @Value("${castellum.viewer.username:#{null}}") String viewerUsername,
            @Value("${castellum.viewer.password-hash:#{null}}") String viewerPasswordHash) {
        this.repository = repository;
        this.auditService = auditService;
        this.adminUsername = adminUsername;
        this.adminPasswordHash = adminPasswordHash;
        this.viewerUsername = viewerUsername;
        this.viewerPasswordHash = viewerPasswordHash;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void bootstrap() {
        mintOrRotate(adminUsername, adminPasswordHash, Role.ADMIN, "ADMIN_HASH_ROTATE");
        mintOrRotate(viewerUsername, viewerPasswordHash, Role.VIEWER, "VIEWER_HASH_ROTATE");
    }

    /** Kept for backward compatibility with tests that call this by name. */
    public void bootstrapAdmin() {
        bootstrap();
    }

    private void mintOrRotate(String username, String passwordHash, Role role, String rotateAuditAction) {
        if (username == null || username.isBlank()
                || passwordHash == null || passwordHash.isBlank()) {
            log.warn("Bootstrap {} skipped: env not set", role);
            return;
        }
        repository.findByUsername(username).ifPresentOrElse(existing -> {
            if (!existing.getPasswordHash().equals(passwordHash)) {
                auditService.recordEvent("bootstrap", rotateAuditAction, "user", username,
                        Map.of("username", username));
                existing.setPasswordHash(passwordHash);
                repository.save(existing);
                log.info("Bootstrap {} password hash updated for {}", role, username);
            }
        }, () -> {
            User u = new User();
            u.setUsername(username);
            u.setPasswordHash(passwordHash);
            u.setRole(role);
            u.setEnabled(true);
            u.setCreatedAt(Instant.now());
            repository.save(u);
            log.info("Bootstrap {} created: {}", role, username);
        });
    }
}

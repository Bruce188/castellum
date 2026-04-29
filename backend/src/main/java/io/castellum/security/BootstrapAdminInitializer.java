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

    public BootstrapAdminInitializer(
            UserRepository repository,
            AuditService auditService,
            @Value("${castellum.admin.username:#{null}}") String adminUsername,
            @Value("${castellum.admin.password-hash:#{null}}") String adminPasswordHash) {
        this.repository = repository;
        this.auditService = auditService;
        this.adminUsername = adminUsername;
        this.adminPasswordHash = adminPasswordHash;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void bootstrapAdmin() {
        if (adminUsername == null || adminUsername.isBlank()
                || adminPasswordHash == null || adminPasswordHash.isBlank()) {
            log.warn("Bootstrap admin skipped: CASTELLUM_ADMIN_USERNAME or CASTELLUM_ADMIN_PASSWORD_HASH not set");
            return;
        }
        repository.findByUsername(adminUsername).ifPresentOrElse(existing -> {
            if (!existing.getPasswordHash().equals(adminPasswordHash)) {
                auditService.recordEvent("bootstrap", "ADMIN_HASH_ROTATE", "user", adminUsername,
                        Map.of("username", adminUsername));
                existing.setPasswordHash(adminPasswordHash);
                repository.save(existing);
                log.info("Bootstrap admin password hash updated for {}", adminUsername);
            }
        }, () -> {
            User u = new User();
            u.setUsername(adminUsername);
            u.setPasswordHash(adminPasswordHash);
            u.setRole(Role.ADMIN);
            u.setEnabled(true);
            u.setCreatedAt(Instant.now());
            repository.save(u);
            log.info("Bootstrap admin created: {}", adminUsername);
        });
    }
}

package io.castellum.security;

import io.castellum.audit.AuditService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.NoSuchElementException;

@RestController
@RequestMapping("/api/users")
@PreAuthorize("hasRole('ADMIN')")
public class UserController {

    private final UserRepository userRepository;
    private final AuditService auditService;

    public UserController(UserRepository userRepository, AuditService auditService) {
        this.userRepository = userRepository;
        this.auditService = auditService;
    }

    @PostMapping("/{username}/disable")
    @Transactional
    public ResponseEntity<Void> disable(@PathVariable String username) {
        User u = userRepository.findByUsername(username)
                .orElseThrow(() -> new NoSuchElementException("user not found: " + username));
        u.setEnabled(false);
        u.setTokenVersion(u.getTokenVersion() + 1);
        userRepository.save(u);
        auditService.recordEvent(currentActor(), "USER_DISABLED", "user", username,
                Map.of("targetUsername", username));
        return ResponseEntity.noContent().build();
    }

    private static String currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "anonymous" : auth.getName();
    }
}

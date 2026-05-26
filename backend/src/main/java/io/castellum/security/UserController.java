package io.castellum.security;

import io.castellum.audit.AuditService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * ADMIN-only user-management surface.
 *
 * <p>Endpoint matrix:
 * <ul>
 *   <li>{@code POST   /api/users}                  → create user (any role, initial password)</li>
 *   <li>{@code GET    /api/users}                  → paginated list (max 200/page)</li>
 *   <li>{@code PUT    /api/users/{u}/role}         → change role (bumps tokenVersion)</li>
 *   <li>{@code POST   /api/users/{u}/disable}      → disable + bump tokenVersion (existing)</li>
 * </ul>
 *
 * <p>Every mutation emits an audit row. {@code passwordHash} is never returned
 * in any response — {@link UserDto} explicitly excludes it.
 */
@RestController
@RequestMapping("/api/users")
@PreAuthorize("hasRole('ADMIN')")
public class UserController {

    private final UserRepository userRepository;
    private final AuditService auditService;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserRepository userRepository, AuditService auditService,
                          PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.auditService = auditService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping
    @Transactional
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody CreateUserRequest req) {
        if (userRepository.findByUsername(req.username()).isPresent()) {
            return ResponseEntity.status(409).build();
        }
        User u = new User();
        u.setUsername(req.username());
        u.setRole(req.role());
        u.setPasswordHash(passwordEncoder.encode(req.initialPassword()));
        u.setEnabled(true);
        u.setCreatedAt(Instant.now());
        u.setTokenVersion(0);
        userRepository.save(u);

        auditService.recordEvent(currentActor(), "USER_CREATE", "user",
                String.valueOf(u.getId()),
                Map.of("username", req.username(), "role", req.role().name()));
        return ResponseEntity.status(201).body(UserDto.from(u));
    }

    @GetMapping
    public Page<UserDto> listUsers(@PageableDefault(size = 50, sort = "username") Pageable pageable) {
        int safeSize = Math.min(pageable.getPageSize(), 200);
        Pageable bounded = pageable.getPageSize() == safeSize
                ? pageable
                : org.springframework.data.domain.PageRequest.of(pageable.getPageNumber(), safeSize, pageable.getSort());
        return userRepository.findAll(bounded).map(UserDto::from);
    }

    @PutMapping("/{username}/role")
    @Transactional
    public UserDto changeRole(@PathVariable String username,
                              @Valid @RequestBody RoleChangeRequest req) {
        User u = userRepository.findByUsername(username)
                .orElseThrow(() -> new NoSuchElementException("user not found: " + username));
        Role previous = u.getRole();
        u.setRole(req.role());
        // Role change invalidates outstanding JWTs — bump tokenVersion so the
        // user is forced to re-authenticate against the new authority set.
        u.setTokenVersion(u.getTokenVersion() + 1);
        userRepository.save(u);

        auditService.recordEvent(currentActor(), "USER_ROLE_CHANGE", "user",
                String.valueOf(u.getId()),
                Map.of("targetUsername", username,
                        "previousRole", previous.name(),
                        "newRole", req.role().name()));
        return UserDto.from(u);
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

    public record CreateUserRequest(
            @NotBlank @Size(min = 1, max = 64)
            @Pattern(regexp = "[A-Za-z0-9._-]+",
                    message = "must contain only letters, digits, dot, underscore, or hyphen")
            String username,
            @NotNull Role role,
            @NotBlank @Size(min = 8, max = 256) String initialPassword) {}

    public record RoleChangeRequest(@NotNull Role role) {}
}

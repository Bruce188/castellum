package io.castellum.security;

import io.castellum.audit.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final AuditService auditService;
    private final LoginRateLimiter rateLimiter;
    private final ClientAddressResolver clientAddressResolver;
    private final PasswordEncoder passwordEncoder;
    private final PasswordChangeRateLimiter passwordChangeRateLimiter;
    private final Set<String> bootstrapUsernames;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private UserRepository userRepository;

    public AuthController(AuthenticationManager authManager, JwtService jwtService,
                          AuditService auditService, LoginRateLimiter rateLimiter,
                          ClientAddressResolver clientAddressResolver,
                          PasswordEncoder passwordEncoder,
                          PasswordChangeRateLimiter passwordChangeRateLimiter,
                          @Value("${castellum.admin.username:#{null}}") String adminUsername,
                          @Value("${castellum.viewer.username:#{null}}") String viewerUsername) {
        this.authManager = authManager;
        this.jwtService = jwtService;
        this.auditService = auditService;
        this.rateLimiter = rateLimiter;
        this.clientAddressResolver = clientAddressResolver;
        this.passwordEncoder = passwordEncoder;
        this.passwordChangeRateLimiter = passwordChangeRateLimiter;
        Set<String> bootstrap = new HashSet<>();
        if (adminUsername != null && !adminUsername.isBlank()) bootstrap.add(adminUsername);
        if (viewerUsername != null && !viewerUsername.isBlank()) bootstrap.add(viewerUsername);
        this.bootstrapUsernames = bootstrap;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest body, HttpServletRequest request) {
        String ip = clientAddressResolver.resolve(request);

        if (!rateLimiter.tryAcquire(ip)) {
            long retryAfter = rateLimiter.retryAfterSeconds(ip);
            String actor = body.username() == null || body.username().isBlank()
                    ? "<unknown>" : body.username();
            auditService.recordEvent(actor, "LOGIN_RATE_LIMIT", "auth", actor,
                    Map.of("ip", ip == null ? "" : ip, "retryAfter", retryAfter));
            return ResponseEntity.status(429)
                    .header("Retry-After", String.valueOf(retryAfter))
                    .build();
        }

        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(body.username(), body.password()));
            List<String> roles = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(a -> a.startsWith("ROLE_") ? a.substring(5) : a)
                    .toList();
            String token;
            boolean mustChangePassword = false;
            if (userRepository != null) {
                java.util.Optional<User> userOpt = userRepository.findByUsername(body.username());
                token = userOpt
                        .map(user -> jwtService.issueToken(body.username(), roles, user.getTokenVersion()))
                        .orElseGet(() -> jwtService.issueToken(body.username(), roles));
                if (userOpt.isPresent()) {
                    User user = userOpt.get();
                    mustChangePassword = (user.getLastLoginAt() == null
                            && bootstrapUsernames.contains(user.getUsername()));
                    user.setLastLoginAt(Instant.now());
                    userRepository.save(user);
                }
            } else {
                token = jwtService.issueToken(body.username(), roles);
            }
            Instant expiresAt = jwtService.parse(token).getPayload().getExpiration().toInstant();
            auditService.recordEvent(body.username(), "LOGIN_SUCCESS", "auth", body.username(),
                    Map.of("ip", ip == null ? "" : ip));
            return ResponseEntity.ok(new LoginResponse(token, expiresAt, roles, mustChangePassword));
        } catch (BadCredentialsException e) {
            String actor = body.username() == null || body.username().isBlank()
                    ? "<unknown>" : body.username();
            rateLimiter.recordFailure(ip);
            auditService.recordEvent(actor, "LOGIN_FAIL", "auth", actor,
                    Map.of("ip", ip == null ? "" : ip, "reason", "bad_credentials"));
            throw e;
        }
    }

    /**
     * Self-service password change for the authenticated caller.
     *
     * <p>Rate-limited per-actor (3 attempts / 60s) — both successful and failed
     * attempts consume budget so a high-frequency attacker can't brute-force
     * {@code oldPassword} via repeated submissions. On success the user's
     * {@code tokenVersion} is bumped so prior JWTs (including the one used to
     * make this very call) are rejected on the next request.
     */
    @PostMapping("/change-password")
    @Transactional
    public ResponseEntity<Void> changePassword(@Valid @RequestBody ChangePasswordRequest body,
                                               Authentication auth) {
        if (auth == null || auth.getName() == null) {
            // Should not occur — SecurityConfig requires auth on /api/auth/change-password —
            // but defend against bypass in case the filter chain is reordered.
            throw new BadCredentialsException("not authenticated");
        }
        String actor = auth.getName();

        if (!passwordChangeRateLimiter.tryAcquire(actor)) {
            long retryAfter = passwordChangeRateLimiter.retryAfterSeconds(actor);
            auditService.recordEvent(actor, "AUTH_PASSWORD_CHANGE_RATE_LIMIT", "auth", actor,
                    Map.of("retryAfter", retryAfter));
            return ResponseEntity.status(429)
                    .header("Retry-After", String.valueOf(retryAfter))
                    .build();
        }
        // Spend budget *before* validating old password so brute-force attempts
        // count even on bad input.
        passwordChangeRateLimiter.recordAttempt(actor);

        if (userRepository == null) {
            // Defensive — production wiring always provides the repo. This branch
            // only fires in unit tests that omit the repo bean. Surface as 503-ish
            // BadCredentials so the caller sees an error instead of NPE.
            throw new BadCredentialsException("user store unavailable");
        }

        User user = userRepository.findByUsername(actor)
                .orElseThrow(() -> new NoSuchElementException("user not found: " + actor));

        if (!passwordEncoder.matches(body.oldPassword(), user.getPasswordHash())) {
            auditService.recordEvent(actor, "AUTH_PASSWORD_CHANGE_DENIED", "user",
                    String.valueOf(user.getId()),
                    Map.of("reason", "old_password_mismatch"));
            throw new BadCredentialsException("oldPassword mismatch");
        }

        // Encode with the BCrypt-12 PasswordEncoder bean — same cost factor as bootstrap hashes.
        user.setPasswordHash(passwordEncoder.encode(body.newPassword()));
        user.setTokenVersion(user.getTokenVersion() + 1);
        userRepository.save(user);

        auditService.recordEvent(actor, "AUTH_PASSWORD_CHANGE", "user",
                String.valueOf(user.getId()),
                Map.of("tokenVersion", user.getTokenVersion()));

        return ResponseEntity.noContent().build();
    }
}

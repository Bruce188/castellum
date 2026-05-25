package io.castellum.security;

import io.castellum.audit.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final AuditService auditService;
    private final LoginRateLimiter rateLimiter;
    private final ClientAddressResolver clientAddressResolver;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private UserRepository userRepository;

    public AuthController(AuthenticationManager authManager, JwtService jwtService,
                          AuditService auditService, LoginRateLimiter rateLimiter,
                          ClientAddressResolver clientAddressResolver) {
        this.authManager = authManager;
        this.jwtService = jwtService;
        this.auditService = auditService;
        this.rateLimiter = rateLimiter;
        this.clientAddressResolver = clientAddressResolver;
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
            if (userRepository != null) {
                java.util.Optional<User> userOpt = userRepository.findByUsername(body.username());
                token = userOpt
                        .map(user -> jwtService.issueToken(body.username(), roles, user.getTokenVersion()))
                        .orElseGet(() -> jwtService.issueToken(body.username(), roles));
                userOpt.ifPresent(user -> {
                    user.setLastLoginAt(Instant.now());
                    userRepository.save(user);
                });
            } else {
                token = jwtService.issueToken(body.username(), roles);
            }
            Instant expiresAt = jwtService.parse(token).getPayload().getExpiration().toInstant();
            auditService.recordEvent(body.username(), "LOGIN_SUCCESS", "auth", body.username(),
                    Map.of("ip", ip == null ? "" : ip));
            return ResponseEntity.ok(new LoginResponse(token, expiresAt, roles));
        } catch (BadCredentialsException e) {
            String actor = body.username() == null || body.username().isBlank()
                    ? "<unknown>" : body.username();
            rateLimiter.recordFailure(ip);
            auditService.recordEvent(actor, "LOGIN_FAIL", "auth", actor,
                    Map.of("ip", ip == null ? "" : ip, "reason", "bad_credentials"));
            throw e;
        }
    }
}

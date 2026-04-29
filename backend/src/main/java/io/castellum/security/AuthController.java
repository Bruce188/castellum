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

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private UserRepository userRepository;

    public AuthController(AuthenticationManager authManager, JwtService jwtService, AuditService auditService) {
        this.authManager = authManager;
        this.jwtService = jwtService;
        this.auditService = auditService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest body, HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(body.username(), body.password()));
            List<String> roles = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(a -> a.startsWith("ROLE_") ? a.substring(5) : a)
                    .toList();
            String token = jwtService.issueToken(body.username(), roles);
            Instant expiresAt = Instant.now().plusSeconds(jwtService.ttlSeconds());
            if (userRepository != null) {
                userRepository.findByUsername(body.username()).ifPresent(user -> {
                    user.setLastLoginAt(Instant.now());
                    userRepository.save(user);
                });
            }
            auditService.recordEvent(body.username(), "LOGIN_SUCCESS", "auth", body.username(),
                    Map.of("ip", ip == null ? "" : ip));
            return ResponseEntity.ok(new LoginResponse(token, expiresAt, roles));
        } catch (BadCredentialsException e) {
            String actor = body.username() == null || body.username().isBlank()
                    ? "<unknown>" : body.username();
            auditService.recordEvent(actor, "LOGIN_FAIL", "auth", actor,
                    Map.of("ip", ip == null ? "" : ip, "reason", "bad_credentials"));
            throw e;
        }
    }
}

package io.castellum.security;

import io.castellum.audit.AuditService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * ADMIN-only remote-agent token lifecycle.
 *
 * <p>Endpoint matrix:
 * <ul>
 *   <li>{@code POST   /api/discovery/remote-docker/tokens}         → create token (201 + plaintext ONCE)</li>
 *   <li>{@code GET    /api/discovery/remote-docker/tokens}         → list metadata (NO hash, NO plaintext)</li>
 *   <li>{@code POST   /api/discovery/remote-docker/tokens/{id}/revoke} → revoke (204)</li>
 * </ul>
 *
 * <p><b>Security invariants:</b>
 * <ul>
 *   <li>Tokens are stored ONLY as BCrypt hashes — plaintext shown ONCE at create, then discarded.</li>
 *   <li>List and revoke responses NEVER include {@code tokenHash} or any plaintext.</li>
 *   <li>Audit details NEVER include the token value.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/discovery/remote-docker/tokens")
@PreAuthorize("hasRole('ADMIN')")
public class RemoteAgentTokenController {

    /** Entropy source for token generation. */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Encoded token length: 32 bytes → 43 URL-safe base64 chars (≥256-bit entropy). */
    private static final int TOKEN_BYTES = 32;

    private final RemoteAgentTokenRepository tokenRepository;
    private final AuditService auditService;
    private final PasswordEncoder passwordEncoder;

    public RemoteAgentTokenController(RemoteAgentTokenRepository tokenRepository,
                                      AuditService auditService,
                                      PasswordEncoder passwordEncoder) {
        this.tokenRepository = tokenRepository;
        this.auditService = auditService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Creates a new remote-agent token. The plaintext token is returned ONCE in the response
     * and never stored. Subsequent list/get calls return metadata only.
     */
    @PostMapping
    @Transactional
    public ResponseEntity<RemoteAgentTokenDto.CreateTokenResponse> create(
            @Valid @RequestBody CreateTokenRequest req) {
        // Generate ≥256-bit token via SecureRandom → URL-safe base64
        byte[] bytes = new byte[TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        String plaintext = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        RemoteAgentToken token = new RemoteAgentToken();
        token.setLabel(req.label());
        token.setTokenHash(passwordEncoder.encode(plaintext));
        token.setCreatedAt(Instant.now());
        token.setCreatedBy(currentActor());
        tokenRepository.save(token);

        // Audit: NO token value in detail
        auditService.recordEvent(currentActor(), "REMOTE_AGENT_TOKEN_CREATE",
                "remote_agent_token", String.valueOf(token.getId()),
                Map.of("label", req.label()));

        return ResponseEntity.status(201)
                .body(new RemoteAgentTokenDto.CreateTokenResponse(token.getId(), token.getLabel(), plaintext));
    }

    /**
     * Lists all tokens — metadata only (no hash, no plaintext).
     */
    @GetMapping
    public List<RemoteAgentTokenDto> list() {
        return tokenRepository.findAll().stream()
                .map(RemoteAgentTokenDto::from)
                .toList();
    }

    /**
     * Revokes a token by id. Sets {@code revoked=true} and {@code revokedAt=now}.
     */
    @PostMapping("/{id}/revoke")
    @Transactional
    public ResponseEntity<Void> revoke(@PathVariable Long id) {
        RemoteAgentToken token = tokenRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("remote agent token not found: " + id));
        token.setRevoked(true);
        token.setRevokedAt(Instant.now());
        tokenRepository.save(token);

        // Audit: NO token value in detail
        auditService.recordEvent(currentActor(), "REMOTE_AGENT_TOKEN_REVOKE",
                "remote_agent_token", String.valueOf(id),
                Map.of("label", token.getLabel()));

        return ResponseEntity.noContent().build();
    }

    private static String currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth == null ? "anonymous" : auth.getName();
    }

    public record CreateTokenRequest(
            @NotBlank @Size(max = 128) String label) {}
}

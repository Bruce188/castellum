package io.castellum.security;

import java.time.Instant;

/**
 * Metadata-only DTO for {@link RemoteAgentToken} returned by the token-management API.
 *
 * <p>Intentionally omits {@code tokenHash} — the hash MUST NOT leave the server.
 * The plaintext token is shown ONCE at create time via {@link CreateTokenResponse}
 * and is never persisted or returned again.
 */
public record RemoteAgentTokenDto(
        Long id,
        String label,
        Instant createdAt,
        String createdBy,
        boolean revoked,
        Instant revokedAt,
        Instant lastUsedAt) {

    public static RemoteAgentTokenDto from(RemoteAgentToken t) {
        return new RemoteAgentTokenDto(
                t.getId(),
                t.getLabel(),
                t.getCreatedAt(),
                t.getCreatedBy(),
                t.isRevoked(),
                t.getRevokedAt(),
                t.getLastUsedAt());
    }

    /**
     * Create-response record carrying the plaintext token ONCE.
     *
     * <p>Returned only by the create endpoint. After this response, the plaintext is
     * discarded — it is not stored, not logged, and cannot be retrieved again.
     */
    public record CreateTokenResponse(Long id, String label, String token) {}
}

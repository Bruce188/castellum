package io.castellum.security;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RemoteAgentTokenRepository extends JpaRepository<RemoteAgentToken, Long> {

    /** Returns all non-revoked tokens — the bounded active set for auth-filter matching. */
    List<RemoteAgentToken> findByRevokedFalse();

    /** Looks up a token by id, returning empty if not found or already revoked. */
    Optional<RemoteAgentToken> findByIdAndRevokedFalse(Long id);
}

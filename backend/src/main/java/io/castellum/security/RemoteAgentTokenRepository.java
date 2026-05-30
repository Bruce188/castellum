package io.castellum.security;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RemoteAgentTokenRepository extends JpaRepository<RemoteAgentToken, Long> {

    /** Returns all non-revoked tokens — the bounded active set for auth-filter matching. */
    List<RemoteAgentToken> findByRevokedFalse();
}

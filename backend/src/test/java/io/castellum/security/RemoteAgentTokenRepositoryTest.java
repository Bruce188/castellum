package io.castellum.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class RemoteAgentTokenRepositoryTest {

    @Autowired
    private RemoteAgentTokenRepository repository;

    private RemoteAgentToken buildToken(String label, String hash) {
        RemoteAgentToken t = new RemoteAgentToken();
        t.setLabel(label);
        t.setTokenHash(hash);
        t.setCreatedAt(Instant.now());
        t.setCreatedBy("test-admin");
        return t;
    }

    @Test
    void saveToken_findByRevokedFalse_returnsIt() {
        RemoteAgentToken saved = repository.save(buildToken("agent-1", "$2a$12$hash1"));
        assertNotNull(saved.getId(), "saved entity must have a generated id");

        List<RemoteAgentToken> active = repository.findByRevokedFalse();
        assertTrue(active.stream().anyMatch(t -> t.getId().equals(saved.getId())),
            "findByRevokedFalse must return the non-revoked token");
        // token_hash persists; NO plaintext field on entity
        assertEquals("$2a$12$hash1", active.stream()
            .filter(t -> t.getId().equals(saved.getId()))
            .findFirst().orElseThrow().getTokenHash(),
            "tokenHash must persist exactly");
    }

    @Test
    void revokeToken_findByRevokedFalse_excludesIt() {
        RemoteAgentToken t = repository.save(buildToken("agent-2", "$2a$12$hash2"));
        t.setRevoked(true);
        t.setRevokedAt(Instant.now());
        repository.save(t);

        List<RemoteAgentToken> active = repository.findByRevokedFalse();
        assertTrue(active.stream().noneMatch(tok -> tok.getId().equals(t.getId())),
            "revoked token must be excluded from findByRevokedFalse");
    }

    @Test
    void findByIdAndRevokedFalse_revokedId_returnsEmpty() {
        RemoteAgentToken t = repository.save(buildToken("agent-3", "$2a$12$hash3"));
        t.setRevoked(true);
        repository.save(t);

        Optional<RemoteAgentToken> result = repository.findByIdAndRevokedFalse(t.getId());
        assertTrue(result.isEmpty(),
            "findByIdAndRevokedFalse must return empty for a revoked token");
    }

    @Test
    void findByIdAndRevokedFalse_activeId_returnsToken() {
        RemoteAgentToken t = repository.save(buildToken("agent-4", "$2a$12$hash4"));

        Optional<RemoteAgentToken> result = repository.findByIdAndRevokedFalse(t.getId());
        assertTrue(result.isPresent(),
            "findByIdAndRevokedFalse must return the token when not revoked");
        assertEquals(t.getId(), result.get().getId());
    }
}

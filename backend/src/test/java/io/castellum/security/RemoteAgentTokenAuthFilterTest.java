package io.castellum.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RemoteAgentTokenAuthFilterTest {

    private RemoteAgentTokenRepository repository;
    private BCryptPasswordEncoder encoder;
    private RemoteAgentTokenAuthFilter filter;

    @BeforeEach
    void setUp() {
        repository = mock(RemoteAgentTokenRepository.class);
        // Use real BCrypt(12) as required by plan
        encoder = new BCryptPasswordEncoder(12);
        filter = new RemoteAgentTokenAuthFilter(repository, encoder);
        SecurityContextHolder.clearContext();
    }

    private HttpServletRequest mockPostRequest(String authHeader) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getRequestURI()).thenReturn(RemoteAgentTokenAuthFilter.INGEST_PATH);
        when(req.getDispatcherType()).thenReturn(jakarta.servlet.DispatcherType.REQUEST);
        when(req.getHeader("Authorization")).thenReturn(authHeader);
        return req;
    }

    private RemoteAgentToken buildActiveToken(String label, String plaintext) {
        RemoteAgentToken t = new RemoteAgentToken();
        t.setLabel(label);
        t.setTokenHash(encoder.encode(plaintext));
        t.setCreatedAt(Instant.now());
        t.setRevoked(false);
        return t;
    }

    @Test
    void validNonRevokedToken_setsPrincipalWithRemoteAgentRole() throws Exception {
        String plaintext = "valid-token-abc123";
        RemoteAgentToken active = buildActiveToken("my-agent", plaintext);
        when(repository.findByRevokedFalse()).thenReturn(List.of(active));
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        HttpServletRequest req = mockPostRequest("Bearer " + plaintext);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(req, res, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth, "authentication must be set on valid token");
        assertTrue(auth.isAuthenticated());
        assertTrue(auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_REMOTE_AGENT")),
            "principal must have ROLE_REMOTE_AGENT authority");
        assertEquals("my-agent", auth.getName());

        // lastUsedAt must be updated
        ArgumentCaptor<RemoteAgentToken> saved = ArgumentCaptor.forClass(RemoteAgentToken.class);
        verify(repository).save(saved.capture());
        assertNotNull(saved.getValue().getLastUsedAt(), "lastUsedAt must be set on match");

        verify(chain).doFilter(req, res);
    }

    @Test
    void missingAuthorizationHeader_noPrincipalSet_chainContinues() throws Exception {
        when(repository.findByRevokedFalse()).thenReturn(List.of());

        HttpServletRequest req = mockPostRequest(null);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(req, res, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication(),
            "no authentication must be set when header is absent");
        verify(chain).doFilter(req, res);
        // repository must NOT be consulted when there is no Bearer header
        verify(repository, never()).findByRevokedFalse();
    }

    @Test
    void nonBearerScheme_noPrincipalSet_chainContinues() throws Exception {
        HttpServletRequest req = mockPostRequest("Basic dXNlcjpwYXNz");
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(req, res, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(chain).doFilter(req, res);
        verify(repository, never()).findByRevokedFalse();
    }

    @Test
    void bearerPresentButMatchesNoActiveRow_noPrincipalSet() throws Exception {
        String plaintext = "unknown-token-xyz";
        RemoteAgentToken otherActive = buildActiveToken("other-agent", "completely-different-token");
        when(repository.findByRevokedFalse()).thenReturn(List.of(otherActive));

        HttpServletRequest req = mockPostRequest("Bearer " + plaintext);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(req, res, chain);

        // Context was empty; no match → still empty (filter does not set auth on no-match).
        assertNull(SecurityContextHolder.getContext().getAuthentication(),
            "no principal must be set when token matches no active row");
        verify(chain).doFilter(req, res);
        // encoder must have been consulted (for the one active row)
        verify(repository).findByRevokedFalse();
        // no save — no match
        verify(repository, never()).save(any());
    }

    @Test
    void revokedTokenOnly_noMatch_contextCleared() throws Exception {
        // findByRevokedFalse returns ONLY non-revoked rows; revoked rows are never in the set.
        // Simulated by returning empty list — the revoked row is excluded by the repo query.
        String plaintext = "revoked-token-secret";
        when(repository.findByRevokedFalse()).thenReturn(List.of()); // no active rows

        HttpServletRequest req = mockPostRequest("Bearer " + plaintext);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(req, res, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication(),
            "revoked token (no active rows) must not authenticate");
        verify(chain).doFilter(req, res);
    }

    @Test
    void matchLoop_consultsEncoderForEachActiveRow() throws Exception {
        String presented = "presented-token";
        // Three active rows; none matches the presented token
        RemoteAgentToken a = buildActiveToken("agent-a", "token-a");
        RemoteAgentToken b = buildActiveToken("agent-b", "token-b");
        RemoteAgentToken c = buildActiveToken("agent-c", "token-c");
        when(repository.findByRevokedFalse()).thenReturn(List.of(a, b, c));

        // Use a spy encoder to count invocations
        BCryptPasswordEncoder spyEncoder = spy(encoder);
        RemoteAgentTokenAuthFilter spyFilter = new RemoteAgentTokenAuthFilter(repository, spyEncoder);

        HttpServletRequest req = mockPostRequest("Bearer " + presented);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        spyFilter.doFilterInternal(req, res, chain);

        // Encoder must be called once per active row (no early-exit)
        verify(spyEncoder, times(3)).matches(eq(presented), anyString());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void shouldNotFilter_nonIngestRoute_returnsTrue() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("GET");
        when(req.getRequestURI()).thenReturn("/api/devices");
        when(req.getDispatcherType()).thenReturn(jakarta.servlet.DispatcherType.REQUEST);

        assertTrue(filter.shouldNotFilter(req),
            "filter must skip non-ingest routes");
    }

    @Test
    void shouldNotFilter_errorDispatch_returnsTrue() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getDispatcherType()).thenReturn(jakarta.servlet.DispatcherType.ERROR);
        when(req.getRequestURI()).thenReturn(RemoteAgentTokenAuthFilter.INGEST_PATH);

        assertTrue(filter.shouldNotFilter(req),
            "filter must skip ERROR-dispatch requests");
    }

    @Test
    void shouldNotFilter_ingestPostRoute_returnsFalse() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getRequestURI()).thenReturn(RemoteAgentTokenAuthFilter.INGEST_PATH);
        when(req.getDispatcherType()).thenReturn(jakarta.servlet.DispatcherType.REQUEST);

        assertFalse(filter.shouldNotFilter(req),
            "filter must not skip POST /api/discovery/remote-docker");
    }
}

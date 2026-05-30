package io.castellum.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

/**
 * Authenticates {@code POST /api/discovery/remote-docker} by bearer token.
 *
 * <p>Clones the bearer-parse shape of {@link JwtAuthenticationFilter} (L72-77).
 * On a valid, non-revoked token match the filter sets an authenticated principal with
 * authority {@code ROLE_REMOTE_AGENT} and updates {@code lastUsedAt}.
 *
 * <p><b>Security invariants (hard constraints):</b>
 * <ul>
 *   <li>The match loop iterates ALL active rows via {@link RemoteAgentTokenRepository#findByRevokedFalse()}
 *       — it does NOT short-circuit on a non-match in a way that leaks timing about whether
 *       a given token is active.</li>
 *   <li>The presented token value is NEVER logged, returned in errors, or stored in any audit
 *       detail. Log entries reference only class-name errors, never token values or validity.</li>
 *   <li>This filter is inert on every route other than {@code POST /api/discovery/remote-docker}
 *       ({@link #shouldNotFilter} returns {@code true} for all others).</li>
 * </ul>
 *
 * <p>Not annotated with {@code @Component} — registered exclusively by {@link io.castellum.config.SecurityConfig}
 * as a {@code @Bean} so that {@code @WebMvcTest} slices (which lack JPA) can operate without
 * a live {@link RemoteAgentTokenRepository}.
 */
public class RemoteAgentTokenAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RemoteAgentTokenAuthFilter.class);

    static final String INGEST_PATH = "/api/discovery/remote-docker";

    private final RemoteAgentTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;

    public RemoteAgentTokenAuthFilter(RemoteAgentTokenRepository tokenRepository,
                                      PasswordEncoder passwordEncoder) {
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Skip this filter for every route EXCEPT {@code POST /api/discovery/remote-docker}.
     * Also skip ERROR-dispatch (mirrors {@link JwtAuthenticationFilter#shouldNotFilter}).
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (request.getDispatcherType() == jakarta.servlet.DispatcherType.ERROR
                || "/error".equals(request.getRequestURI())) {
            return true;
        }
        return !(HttpMethod.POST.matches(request.getMethod())
                && INGEST_PATH.equals(request.getRequestURI()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            // No bearer header — pass through; downstream auth will yield 401.
            chain.doFilter(request, response);
            return;
        }
        String presented = header.substring(7);

        List<RemoteAgentToken> activeTokens = tokenRepository.findByRevokedFalse();
        RemoteAgentToken matched = null;

        // Iterate ALL active rows — do not early-exit on a non-match to avoid timing leakage.
        for (RemoteAgentToken candidate : activeTokens) {
            if (passwordEncoder.matches(presented, candidate.getTokenHash())) {
                matched = candidate;
                // Continue the loop — constant-time over all active rows.
            }
        }

        if (matched != null) {
            // Update lastUsedAt on the last matched token (matched is the last winning row).
            matched.setLastUsedAt(Instant.now());
            tokenRepository.save(matched);

            var auth = new UsernamePasswordAuthenticationToken(
                    matched.getLabel(), null,
                    List.of(new SimpleGrantedAuthority("ROLE_REMOTE_AGENT")));
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
            log.debug("RemoteAgentTokenAuthFilter: authenticated agent '{}'", matched.getLabel());
        } else {
            // No matching active token — do NOT clear context (a JWT filter downstream may
            // still authenticate the request with a different authority, e.g. ROLE_ADMIN).
            // SECURITY: do NOT log the presented token value or match outcome.
            log.debug("RemoteAgentTokenAuthFilter: no matching active remote-agent token");
        }

        chain.doFilter(request, response);
    }
}

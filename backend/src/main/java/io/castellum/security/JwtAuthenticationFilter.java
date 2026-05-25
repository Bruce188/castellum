package io.castellum.security;

import io.castellum.audit.AuditService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /** Request attribute key under which the parsed {@link Jws} is cached for the lifetime of the request. */
    static final String JWT_CLAIMS_ATTR = "io.castellum.security.jwtClaims";

    private final JwtService jwtService;
    private final AuditService auditService;
    private final UserRepository userRepository;

    @org.springframework.beans.factory.annotation.Autowired
    public JwtAuthenticationFilter(JwtService jwtService, AuditService auditService,
                                   UserRepository userRepository) {
        this.jwtService = jwtService;
        this.auditService = auditService;
        this.userRepository = userRepository;
    }

    /** Single-arg constructor retained for unit tests that instantiate directly. */
    JwtAuthenticationFilter(JwtService jwtService) {
        this(jwtService, null, null);
    }

    /** Two-arg constructor for unit tests that need auditService but not userRepository. */
    JwtAuthenticationFilter(JwtService jwtService, AuditService auditService) {
        this(jwtService, auditService, null);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }
        String token = header.substring(7);
        try {
            // Parse once and cache under request attribute to avoid repeated cryptographic work
            Jws<Claims> jws = jwtService.extractClaims(token);
            request.setAttribute(JWT_CLAIMS_ATTR, jws);

            String username = jwtService.extractUsername(jws);
            List<String> roles = jwtService.extractRoles(jws);

            if (userRepository != null) {
                Optional<User> userOpt = userRepository.findByUsernameAndEnabledTrue(username);
                if (userOpt.isEmpty()) {
                    SecurityContextHolder.clearContext();
                    if (auditService != null) {
                        auditService.recordEvent(username, "AUTH_TOKEN_REJECT", "auth", null,
                                Map.of("reason", "user_disabled_or_missing"));
                    }
                    chain.doFilter(request, response);
                    return;
                }
                int tokenTv = jwtService.extractTokenVersion(jws);
                if (tokenTv != userOpt.get().getTokenVersion()) {
                    SecurityContextHolder.clearContext();
                    if (auditService != null) {
                        auditService.recordEvent(username, "AUTH_TOKEN_REJECT", "auth", null,
                                Map.of("reason", "token_version_mismatch"));
                    }
                    chain.doFilter(request, response);
                    return;
                }
            }

            var auth = new UsernamePasswordAuthenticationToken(
                    username, null,
                    roles.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r)).toList());
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (JwtException e) {
            SecurityContextHolder.clearContext();
            log.warn("JWT validation failed: {}", e.getClass().getSimpleName());
            if (auditService != null) {
                auditService.recordEvent("anonymous", "AUTH_TOKEN_REJECT", "auth", null,
                        Map.of("reason", e.getClass().getSimpleName()));
            }
        }
        chain.doFilter(request, response);
    }
}

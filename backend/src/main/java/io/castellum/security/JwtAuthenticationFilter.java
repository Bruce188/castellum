package io.castellum.security;

import io.castellum.audit.AuditService;
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

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtService jwtService;
    private final AuditService auditService;

    @org.springframework.beans.factory.annotation.Autowired
    public JwtAuthenticationFilter(JwtService jwtService, AuditService auditService) {
        this.jwtService = jwtService;
        this.auditService = auditService;
    }

    /** Single-arg constructor retained for unit tests that instantiate directly. */
    JwtAuthenticationFilter(JwtService jwtService) {
        this(jwtService, null);
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
            String username = jwtService.extractUsername(token);
            List<String> roles = jwtService.extractRoles(token);
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

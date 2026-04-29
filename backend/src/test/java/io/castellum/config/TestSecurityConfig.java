package io.castellum.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.util.Map;

/**
 * Shared test configuration for WebMvcTest slices.
 * Provides real-enough RbacAccessDeniedHandler and RbacAuthenticationEntryPoint
 * without requiring a full AuditService (writes are no-ops; status codes are correct).
 */
@TestConfiguration
public class TestSecurityConfig {

    private final ObjectMapper om = new ObjectMapper();

    @Bean
    @Primary
    public RbacAccessDeniedHandler testRbacAccessDeniedHandler() {
        return new RbacAccessDeniedHandler(null, om) {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response,
                               AccessDeniedException accessDeniedException) throws IOException {
                response.setStatus(403);
                response.setContentType("application/json");
                om.writeValue(response.getWriter(),
                    Map.of("error", "forbidden", "status", 403, "path", request.getRequestURI()));
            }
        };
    }

    @Bean
    @Primary
    public RbacAuthenticationEntryPoint testRbacAuthenticationEntryPoint() {
        return new RbacAuthenticationEntryPoint(om) {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response,
                                 AuthenticationException authException) throws IOException {
                response.setStatus(401);
                response.setContentType("application/json");
                om.writeValue(response.getWriter(),
                    Map.of("error", "Unauthorized", "status", 401, "path", request.getRequestURI()));
            }
        };
    }
}

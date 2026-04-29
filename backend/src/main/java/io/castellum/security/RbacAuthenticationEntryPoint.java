package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
public class RbacAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper om;

    public RbacAuthenticationEntryPoint(ObjectMapper om) {
        this.om = om;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
            throws IOException {
        response.setStatus(401);
        response.setContentType("application/json");
        om.writeValue(response.getWriter(), Map.of("error", "unauthorized", "status", 401, "path", request.getRequestURI()));
    }
}

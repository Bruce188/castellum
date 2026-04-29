package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
public class RbacAccessDeniedHandler implements AccessDeniedHandler {

    private final AuditService auditService;
    private final ObjectMapper om;

    public RbacAccessDeniedHandler(AuditService auditService, ObjectMapper om) {
        this.auditService = auditService;
        this.om = om;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e)
            throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String actor = auth == null ? "anonymous" : auth.getName();
        String resourceId = request.getMethod() + " " + request.getRequestURI();
        auditService.recordEvent(actor, "RBAC_DENY", "rbac", resourceId, Map.of("requiredRole", "n/a"));

        response.setStatus(403);
        response.setContentType("application/json");
        om.writeValue(response.getWriter(), Map.of("error", "forbidden", "status", 403, "path", request.getRequestURI()));
    }
}

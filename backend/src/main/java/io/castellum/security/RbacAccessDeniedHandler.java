package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;

import java.io.IOException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class RbacAccessDeniedHandler implements AccessDeniedHandler {

    private final AuditService auditService;
    private final ObjectMapper om;

    public RbacAccessDeniedHandler(@org.springframework.lang.Nullable AuditService auditService, ObjectMapper om) {
        this.auditService = auditService;
        this.om = om;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e)
            throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String actor = auth == null ? "anonymous" : auth.getName();
        String resourceId = request.getMethod() + " " + request.getRequestURI();

        Object handler = request.getAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE);
        String requiredRole = "<unmapped>";
        if (handler instanceof HandlerMethod hm) {
            PreAuthorize pa = hm.getMethodAnnotation(PreAuthorize.class);
            if (pa == null) {
                pa = hm.getBeanType().getAnnotation(PreAuthorize.class);
            }
            if (pa != null) {
                requiredRole = extractRoles(pa.value());
            }
        }

        if (auditService != null) {
            auditService.recordEvent(actor, "RBAC_DENY", "rbac", resourceId, Map.of("requiredRole", requiredRole));
        }

        response.setStatus(403);
        response.setContentType("application/json");
        om.writeValue(response.getWriter(), Map.of("error", "forbidden", "status", 403, "path", request.getRequestURI()));
    }

    static String extractRoles(String expr) {
        Matcher single = Pattern.compile("hasRole\\(['\"]([^'\"]+)['\"]\\)").matcher(expr);
        if (single.find()) {
            return single.group(1);
        }
        Matcher multi = Pattern.compile("hasAnyRole\\(([^)]+)\\)").matcher(expr);
        if (multi.find()) {
            String[] tokens = multi.group(1).split(",");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < tokens.length; i++) {
                String t = tokens[i].trim().replace("'", "").replace("\"", "");
                if (i > 0) sb.append(",");
                sb.append(t);
            }
            return sb.toString();
        }
        return "<unmapped>";
    }
}

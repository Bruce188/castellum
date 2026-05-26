package io.castellum.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;

import java.lang.reflect.Method;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RbacAccessDeniedHandlerTest {

    private final AuditService auditService = mock(AuditService.class);
    private final ObjectMapper om = new ObjectMapper();
    private final RbacAccessDeniedHandler handler = new RbacAccessDeniedHandler(auditService, om);

    @PreAuthorize("hasRole('ADMIN')")
    static class AdminOnlyController {
        void method() {}
    }

    @PreAuthorize("hasAnyRole('ADMIN','VIEWER')")
    static class MultiRoleController {
        void method() {}
    }

    static class UnannotatedController {
        void method() {}
    }

    @PreAuthorize("hasRole(\"ADMIN\")")
    static class AdminDoubleQuoteController {
        void method() {}
    }

    @PreAuthorize("hasAnyRole(\"ADMIN\",\"VIEWER\")")
    static class MultiRoleDoubleQuoteController {
        void method() {}
    }

    @PreAuthorize("hasAnyRole('ADMIN',\"VIEWER\")")
    static class MultiRoleMixedQuoteController {
        void method() {}
    }

    @Test
    void extractsHasRoleSingle() throws Exception {
        invokeWithHandler(AdminOnlyController.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> cap = ArgumentCaptor.forClass(Map.class);
        verify(auditService).recordEvent(any(), eq("RBAC_DENY"), eq("rbac"), any(), cap.capture());
        assertThat(cap.getValue()).containsEntry("requiredRole", "ADMIN");
    }

    @Test
    void extractsHasAnyRoleMultiple() throws Exception {
        invokeWithHandler(MultiRoleController.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> cap = ArgumentCaptor.forClass(Map.class);
        verify(auditService).recordEvent(any(), eq("RBAC_DENY"), eq("rbac"), any(), cap.capture());
        assertThat(cap.getValue()).containsEntry("requiredRole", "ADMIN,VIEWER");
    }

    @Test
    void unmappedRouteReturnsUnmappedSentinel() throws Exception {
        invokeWithoutHandler();
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> cap = ArgumentCaptor.forClass(Map.class);
        verify(auditService).recordEvent(any(), eq("RBAC_DENY"), eq("rbac"), any(), cap.capture());
        assertThat(cap.getValue()).containsEntry("requiredRole", "<unmapped>");
    }

    @Test
    void unannotatedHandlerReturnsUnmappedSentinel() throws Exception {
        invokeWithHandler(UnannotatedController.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> cap = ArgumentCaptor.forClass(Map.class);
        verify(auditService).recordEvent(any(), eq("RBAC_DENY"), eq("rbac"), any(), cap.capture());
        assertThat(cap.getValue()).containsEntry("requiredRole", "<unmapped>");
    }

    @Test
    void extractsHasRoleDoubleQuote() throws Exception {
        invokeWithHandler(AdminDoubleQuoteController.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> cap = ArgumentCaptor.forClass(Map.class);
        verify(auditService).recordEvent(any(), eq("RBAC_DENY"), eq("rbac"), any(), cap.capture());
        assertThat(cap.getValue()).containsEntry("requiredRole", "ADMIN");
    }

    @Test
    void extractsHasAnyRoleDoubleQuote() throws Exception {
        invokeWithHandler(MultiRoleDoubleQuoteController.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> cap = ArgumentCaptor.forClass(Map.class);
        verify(auditService).recordEvent(any(), eq("RBAC_DENY"), eq("rbac"), any(), cap.capture());
        assertThat(cap.getValue()).containsEntry("requiredRole", "ADMIN,VIEWER");
    }

    @Test
    void extractsHasAnyRoleMixedQuotes() throws Exception {
        invokeWithHandler(MultiRoleMixedQuoteController.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> cap = ArgumentCaptor.forClass(Map.class);
        verify(auditService).recordEvent(any(), eq("RBAC_DENY"), eq("rbac"), any(), cap.capture());
        assertThat(cap.getValue()).containsEntry("requiredRole", "ADMIN,VIEWER");
    }

    private void invokeWithHandler(Class<?> controllerClass) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/x");
        Method m = controllerClass.getDeclaredMethod("method");
        Object bean = controllerClass.getDeclaredConstructor().newInstance();
        HandlerMethod hm = new HandlerMethod(bean, m);
        req.setAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE, hm);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        handler.handle(req, resp, new AccessDeniedException("denied"));
    }

    private void invokeWithoutHandler() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/x");
        MockHttpServletResponse resp = new MockHttpServletResponse();
        handler.handle(req, resp, new AccessDeniedException("denied"));
    }
}

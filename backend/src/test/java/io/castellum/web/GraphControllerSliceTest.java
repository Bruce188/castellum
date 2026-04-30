package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.graph.GraphService;
import io.castellum.graph.dto.ShortestPathResponse;
import io.castellum.security.CastellumUserDetailsService;
import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.JwtService;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(GraphController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, RbacAccessDeniedHandler.class, RbacAuthenticationEntryPoint.class})
@WithMockUser(roles = "ADMIN")
class GraphControllerSliceTest {

    @Autowired MockMvc mvc;
    @MockBean AuditService auditService;
    @MockBean GraphService graphService;
    @MockBean CastellumUserDetailsService castellumUserDetailsService;
    @MockBean JwtService jwtService;
    @MockBean UserRepository userRepository;

    private static ShortestPathResponse emptyResponse() {
        return new ShortestPathResponse(1L, 2L, List.of(), 0, BigDecimal.ZERO, false);
    }

    @Test
    void admin_canRead_returns200() throws Exception {
        when(graphService.shortestPath(anyLong(), anyLong())).thenReturn(emptyResponse());

        mvc.perform(get("/api/graph/shortest-path").param("from", "1").param("to", "2"))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void viewer_canRead_returns200() throws Exception {
        when(graphService.shortestPath(anyLong(), anyLong())).thenReturn(emptyResponse());

        mvc.perform(get("/api/graph/shortest-path").param("from", "1").param("to", "2"))
            .andExpect(status().isOk());
    }

    @Test
    void anon_returns401() throws Exception {
        mvc.perform(get("/api/graph/shortest-path")
                .with(anonymous())
                .param("from", "1").param("to", "2"))
            .andExpect(status().isUnauthorized());
    }
}

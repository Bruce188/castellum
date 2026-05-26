package io.castellum.audit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class AuditViewerRbacDenialTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    AuditLogRepository auditRepository;

    @Test
    @WithMockUser(username = "test-viewer", roles = "VIEWER")
    void viewerHitsAuditList_returns403_andEmitsRbacDeniedRow() throws Exception {
        // Handler emits "RBAC_DENY" (confirmed from RbacAccessDeniedHandler source)
        long before = auditRepository.findAll().stream()
            .filter(r -> "RBAC_DENY".equals(r.getAction()))
            .count();

        mvc.perform(get("/api/audit"))
            .andExpect(status().isForbidden());

        long after = auditRepository.findAll().stream()
            .filter(r -> "RBAC_DENY".equals(r.getAction()))
            .count();

        assertThat(after).isGreaterThan(before);
    }
}

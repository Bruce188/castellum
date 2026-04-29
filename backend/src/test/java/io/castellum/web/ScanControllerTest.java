package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.config.SecurityConfig;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ScanController.class)
@Import(SecurityConfig.class)
class ScanControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ScanRepository scanRepository;

    @MockBean
    private AuditService auditService;

    @Test
    void postScan_validRequest_returns202WithId() throws Exception {
        Scan saved = new Scan();
        saved.setId(42L);
        saved.setCidr("192.168.1.0/24");
        saved.setScanType("PING_SWEEP");
        saved.setStatus(ScanStatus.PENDING);

        when(scanRepository.save(any(Scan.class))).thenReturn(saved);

        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.id").value(42));

        verify(auditService).recordEvent(eq("system"), eq("SCAN_SUBMIT"), eq("scan"), anyString(), any());
    }

    @Test
    void postScan_invalidCidr_returns400() throws Exception {
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"not-a-cidr\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void postScan_invalidType_returns400() throws Exception {
        mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"INVALID_TYPE\"}"))
            .andExpect(status().isBadRequest());
    }
}

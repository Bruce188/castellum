package io.castellum.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.config.SecurityConfig;
import io.castellum.ot.OtFingerprintService;
import io.castellum.ot.OtFingerprintService.OtProbeResult;
import io.castellum.ot.OtProtocol;
import io.castellum.ot.OtProbeDecodeException;
import io.castellum.ot.OtProbeNotImplementedException;
import io.castellum.ot.OtProbeTimeoutException;
import io.castellum.ot.OtProbeUnreachableException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(OtProbeController.class)
@Import(SecurityConfig.class)
class OtProbeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private OtFingerprintService otFingerprintService;

    private static final OtProbeResult MOCK_RESULT = new OtProbeResult(
        1L, 2L, OtProtocol.MODBUS_TCP, "127.0.0.1", 502,
        "Castellum-Test", "MOCK-1", "1.0",
        Map.of("0", "Castellum-Test", "1", "MOCK-1"),
        Instant.EPOCH
    );

    @Test
    void probe_validRequest_returns200() throws Exception {
        when(otFingerprintService.probe(anyString(), anyInt(), any(OtProtocol.class)))
            .thenReturn(MOCK_RESULT);

        mockMvc.perform(post("/api/ot-probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"host\":\"127.0.0.1\",\"port\":502,\"protocol\":\"MODBUS_TCP\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.vendor").value("Castellum-Test"))
            .andExpect(jsonPath("$.deviceId").value(1))
            .andExpect(jsonPath("$.serviceId").value(2));
    }

    @Test
    void probe_missingField_returns400() throws Exception {
        mockMvc.perform(post("/api/ot-probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"host\":\"127.0.0.1\",\"protocol\":\"MODBUS_TCP\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void probe_portOutOfRange_returns400() throws Exception {
        mockMvc.perform(post("/api/ot-probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"host\":\"127.0.0.1\",\"port\":70000,\"protocol\":\"MODBUS_TCP\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void probe_invalidHost_returns400WhenServiceThrowsIllegalArgument() throws Exception {
        when(otFingerprintService.probe(anyString(), anyInt(), any(OtProtocol.class)))
            .thenThrow(new IllegalArgumentException("Invalid or disallowed IPv4 address: hostname.example.com"));

        mockMvc.perform(post("/api/ot-probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"host\":\"hostname.example.com\",\"port\":502,\"protocol\":\"MODBUS_TCP\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void probe_unknownProtocol_returns400() throws Exception {
        mockMvc.perform(post("/api/ot-probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"host\":\"127.0.0.1\",\"port\":502,\"protocol\":\"UNKNOWN_PROTO\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void probe_unreachable_returns502() throws Exception {
        when(otFingerprintService.probe(anyString(), anyInt(), any(OtProtocol.class)))
            .thenThrow(new OtProbeUnreachableException("connection refused"));

        mockMvc.perform(post("/api/ot-probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"host\":\"127.0.0.1\",\"port\":502,\"protocol\":\"MODBUS_TCP\"}"))
            .andExpect(status().isBadGateway())
            .andExpect(jsonPath("$.error").value("ot_probe_unreachable"));
    }

    @Test
    void probe_timeout_returns504() throws Exception {
        when(otFingerprintService.probe(anyString(), anyInt(), any(OtProtocol.class)))
            .thenThrow(new OtProbeTimeoutException("read timeout"));

        mockMvc.perform(post("/api/ot-probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"host\":\"127.0.0.1\",\"port\":502,\"protocol\":\"MODBUS_TCP\"}"))
            .andExpect(status().isGatewayTimeout())
            .andExpect(jsonPath("$.error").value("ot_probe_timeout"));
    }

    @Test
    void probe_decodeFailure_returns502() throws Exception {
        when(otFingerprintService.probe(anyString(), anyInt(), any(OtProtocol.class)))
            .thenThrow(new OtProbeDecodeException("unexpected function code"));

        mockMvc.perform(post("/api/ot-probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"host\":\"127.0.0.1\",\"port\":502,\"protocol\":\"MODBUS_TCP\"}"))
            .andExpect(status().isBadGateway())
            .andExpect(jsonPath("$.error").value("ot_probe_decode_failure"));
    }

    @Test
    void probe_notImplemented_returns501() throws Exception {
        when(otFingerprintService.probe(anyString(), anyInt(), any(OtProtocol.class)))
            .thenThrow(new OtProbeNotImplementedException("Protocol not yet implemented"));

        mockMvc.perform(post("/api/ot-probe")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"host\":\"127.0.0.1\",\"port\":502,\"protocol\":\"MODBUS_TCP\"}"))
            .andExpect(status().isNotImplemented())
            .andExpect(jsonPath("$.error").value("ot_probe_not_implemented"));
    }
}

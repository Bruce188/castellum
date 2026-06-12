package io.castellum.web;

import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssClient;
import io.castellum.risk.KevClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end pin of the GRAPH_TOO_LARGE 503 contract: when the device corpus exceeds
 * {@code castellum.graph.max-devices}, {@code GraphBuilder.build()} throws
 * {@code GraphTooLargeException} and {@code GlobalExceptionHandler} surfaces it as
 * HTTP 503 with the {@code {"error":"GRAPH_TOO_LARGE","message":...}} body shape.
 *
 * <p>The limit is pinned to 2 via the {@code properties} attribute so seeding three
 * devices reliably trips the guard through the real controller → service → builder →
 * advice chain (no mocked service).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "castellum.graph.max-devices=2")
@AutoConfigureMockMvc
// Use @WithMockUser for all test methods — the full Spring Security chain is active.
@WithMockUser(roles = "ADMIN")
class GraphControllerGraphTooLargeTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private DeviceRepository deviceRepo;
    @Autowired private NetworkServiceRepository serviceRepo;

    // Stub external feed clients to keep the test hermetic.
    @MockBean private EpssClient epssClient;
    @MockBean private KevClient kevClient;

    @BeforeEach
    void cleanState() {
        serviceRepo.deleteAll();
        deviceRepo.deleteAll();
    }

    @AfterEach
    void teardown() {
        serviceRepo.deleteAll();
        deviceRepo.deleteAll();
    }

    @Test
    void getShortestPath_deviceCountOverMaxDevices_returns503GraphTooLarge() throws Exception {
        // Seed 3 devices against a max-devices limit of 2.
        Device d1 = deviceRepo.save(new Device(null, "10.0.0.10", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM));
        Device d2 = deviceRepo.save(new Device(null, "10.0.0.20", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM));
        deviceRepo.save(new Device(null, "10.0.0.30", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM));

        mockMvc.perform(get("/api/graph/shortest-path")
                .param("from", String.valueOf(d1.getId()))
                .param("to", String.valueOf(d2.getId())))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.error").value("GRAPH_TOO_LARGE"))
            .andExpect(jsonPath("$.message").value(containsString("max-devices")));
    }
}

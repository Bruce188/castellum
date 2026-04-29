package io.castellum;

import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AcceptanceSmokeTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ScanRepository scanRepository;

    @Test
    void postScan_returnsAcceptedWithPositiveLongId_andRowIsPending() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"cidr\":\"192.168.1.0/24\",\"type\":\"PING_SWEEP\"}"))
            .andExpect(status().isAccepted())
            .andReturn();

        String body = result.getResponse().getContentAsString();
        assertTrue(body.contains("\"id\""), "Response should contain 'id' field: " + body);

        // Extract the id from the response JSON
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        Long id = mapper.readTree(body).get("id").asLong();
        assertTrue(id > 0, "id should be a positive Long, got: " + id);

        // AC#2: verify the row exists with status PENDING
        assertTrue(scanRepository.findById(id).isPresent(), "Scan row should exist for id: " + id);
        assertEquals(ScanStatus.PENDING, scanRepository.findById(id).get().getStatus());
    }
}

package io.castellum.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.*;

class FeedsStatusDtoTest {

    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    void serialization_includesEpssKevNvdKeys() throws Exception {
        FeedsStatusDto dto = new FeedsStatusDto(
            new FeedsStatusDto.EpssStatus(LocalDate.of(2025, 1, 1), 1000L),
            new FeedsStatusDto.KevStatus(Instant.parse("2025-01-01T00:00:00Z"), 200L),
            new FeedsStatusDto.NvdStatus(Instant.parse("2025-01-01T00:00:00Z"), 42L)
        );

        String json = mapper.writeValueAsString(dto);
        JsonNode node = mapper.readTree(json);

        assertTrue(node.has("epss"), "should have epss key");
        assertTrue(node.has("kev"), "should have kev key");
        assertTrue(node.has("nvd"), "should have nvd key");
    }

    @Test
    void nvdRowCount_roundTrips() throws Exception {
        FeedsStatusDto dto = new FeedsStatusDto(
            new FeedsStatusDto.EpssStatus(LocalDate.of(2025, 1, 1), 0L),
            new FeedsStatusDto.KevStatus(null, 0L),
            new FeedsStatusDto.NvdStatus(null, 99L)
        );

        String json = mapper.writeValueAsString(dto);
        FeedsStatusDto parsed = mapper.readValue(json, FeedsStatusDto.class);

        assertEquals(99L, parsed.nvd().rowCount(), "nvd.rowCount must round-trip");
    }

    @Test
    void nvdNullLastModified_serializesAsNull() throws Exception {
        FeedsStatusDto dto = new FeedsStatusDto(
            new FeedsStatusDto.EpssStatus(null, 0L),
            new FeedsStatusDto.KevStatus(null, 0L),
            new FeedsStatusDto.NvdStatus(null, 0L)
        );

        String json = mapper.writeValueAsString(dto);
        JsonNode nvd = mapper.readTree(json).get("nvd");

        assertTrue(nvd.get("lastModified").isNull(), "null lastModified must serialize as JSON null");
    }
}

package io.castellum.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@Import({AuditService.class, JacksonAutoConfiguration.class})
class AuditServiceTest {

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void recordEvent_persistsOneRowWithCorrectFields() {
        auditService.recordEvent("system", "TEST_ACTION", "test", "1", Map.of("k", "v"));

        List<AuditLog> rows = auditLogRepository.findAll();
        assertEquals(1, rows.size());

        AuditLog row = rows.get(0);
        assertEquals("system", row.getActor());
        assertEquals("TEST_ACTION", row.getAction());
        assertEquals("test", row.getResourceType());
        assertEquals("1", row.getResourceId());
        assertNotNull(row.getOccurredAt());
    }

    @Test
    void recordEvent_payloadRoundTrips() throws Exception {
        auditService.recordEvent("system", "TEST_ACTION", "test", "2", Map.of("k", "v"));

        List<AuditLog> rows = auditLogRepository.findAll();
        String payloadJson = rows.get(0).getPayload();

        Map<?, ?> deserialized = objectMapper.readValue(payloadJson, Map.class);
        assertEquals("v", deserialized.get("k"));
    }
}

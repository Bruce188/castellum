package io.castellum.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AuditServiceActorSanitizeTest {

    private final AuditLogRepository repo = mock(AuditLogRepository.class);
    private final AuditService service = new AuditService(repo, new ObjectMapper());

    @Test
    void controlCharsReplaced() {
        service.recordEvent("\nROLE_ADMIN\rgranted", "X", "auth", null, Map.of());
        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(repo).save(captor.capture());
        assertEquals("_ROLE_ADMIN_granted", captor.getValue().getActor());
    }

    @Test
    void actorTruncatedTo64Chars() {
        String hundred = "a".repeat(100);
        service.recordEvent(hundred, "X", "auth", null, Map.of());
        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(repo).save(captor.capture());
        assertEquals(64, captor.getValue().getActor().length());
    }

    @Test
    void nullActorBecomesUnknown() {
        service.recordEvent(null, "X", "auth", null, Map.of());
        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(repo).save(captor.capture());
        assertEquals("unknown", captor.getValue().getActor());
    }
}

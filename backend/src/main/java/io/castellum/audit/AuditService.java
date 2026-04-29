package io.castellum.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditLogRepository repository;
    private final ObjectMapper objectMapper;

    public AuditService(AuditLogRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    public AuditLog recordEvent(String actor, String action, String resourceType, String resourceId, Object payload) {
        String payloadJson = serializePayload(payload, resourceType, resourceId);
        AuditLog event = new AuditLog(Instant.now(), sanitizeActor(actor), action, resourceType, resourceId, payloadJson);
        return repository.save(event);
    }

    private String sanitizeActor(String actor) {
        if (actor == null) return "unknown";
        String stripped = actor.replaceAll("[\\p{Cntrl}]", "_");
        return stripped.length() > 64 ? stripped.substring(0, 64) : stripped;
    }

    private String serializePayload(Object payload, String resourceType, String resourceId) {
        if (payload == null) return null;
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            log.warn("Audit payload serialization failed for {}/{}: {}", resourceType, resourceId, e.getMessage());
            return "\"<unserializable>\"";
        }
    }
}

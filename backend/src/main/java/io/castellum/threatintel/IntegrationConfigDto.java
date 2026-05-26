package io.castellum.threatintel;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Request / response DTOs for {@link IntegrationConfigController}. The wire
 * shape is intentionally decoupled from {@link IntegrationConfig} so we never
 * accidentally serialize the encrypted credential bytes.
 */
public class IntegrationConfigDto {

    /** PUT body. {@code config} is JSON-serialized into {@code config_json}; {@code credentials} is encrypted. */
    public record SaveRequest(Map<String, Object> config, String credentials) {}

    /** Public projection: NEVER includes the encrypted credential bytes. */
    public record Response(
            Long id,
            String integrationType,
            Map<String, Object> config,
            boolean credentialsSet,
            Instant lastPushAt,
            String lastPushStatus,
            Instant createdAt,
            Instant updatedAt) {

        private static final ObjectMapper LOCAL = new ObjectMapper();
        private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

        public static Response from(IntegrationConfig cfg) {
            Map<String, Object> config = new LinkedHashMap<>();
            if (cfg.getConfigJson() != null && !cfg.getConfigJson().isBlank()) {
                try {
                    config.putAll(LOCAL.readValue(cfg.getConfigJson(), MAP_TYPE));
                } catch (Exception ignored) {
                    // Unparseable config_json — surface as empty map so the UI still loads.
                }
            }
            return new Response(
                cfg.getId(),
                cfg.getIntegrationType(),
                config,
                cfg.getEncryptedCredentials() != null && cfg.getEncryptedCredentials().length > 0,
                cfg.getLastPushAt(),
                cfg.getLastPushStatus(),
                cfg.getCreatedAt(),
                cfg.getUpdatedAt()
            );
        }
    }

    /** Push outcome surfaced inline in the UI. */
    public record PushResponse(
            String status,             // "ok" or "error"
            String bundleId,           // null on error
            Instant pushedAt,
            String lastPushStatus) {}
}

package io.castellum.threatintel;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditService;
import io.castellum.security.AesGcmCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * ADMIN-only CRUD + push for TAXII / MISP integrations. Persists
 * non-secret config + AES-256-GCM encrypted credentials, delegates the
 * actual push to {@link ThreatIntelService} so the existing TAXII/MISP
 * clients (and their retry/backoff logic) remain the single source of
 * push behaviour.
 *
 * <p>The {@code last_push_at} / {@code last_push_status} columns are
 * updated on every push so the UI can surface the most recent result
 * inline; failures land here too so the operator sees what went wrong
 * without needing audit-log access.
 */
@RestController
@RequestMapping("/api/integrations")
public class IntegrationConfigController {

    private static final Logger log = LoggerFactory.getLogger(IntegrationConfigController.class);

    public static final String TYPE_TAXII = "TAXII";
    public static final String TYPE_MISP = "MISP";

    private final IntegrationConfigRepository repository;
    private final AesGcmCipher cipher;
    private final ThreatIntelService threatIntelService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    public IntegrationConfigController(IntegrationConfigRepository repository,
                                       AesGcmCipher cipher,
                                       ThreatIntelService threatIntelService,
                                       AuditService auditService,
                                       ObjectMapper objectMapper) {
        this.repository = repository;
        this.cipher = cipher;
        this.threatIntelService = threatIntelService;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
    }

    /** Returns the persisted config minus the encrypted-credentials bytes. */
    @GetMapping("/{type}")
    @PreAuthorize("hasRole('ADMIN')")
    public IntegrationConfigDto.Response get(@PathVariable("type") String type) {
        String normalized = normalizeType(type);
        IntegrationConfig cfg = repository.findByIntegrationType(normalized)
            .orElseThrow(() -> new NoSuchElementException(
                "integration_config not found for type: " + normalized));
        return IntegrationConfigDto.Response.from(cfg);
    }

    /** Creates or replaces the config for the given type. Encrypts {@code credentials}. */
    @PutMapping("/{type}")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public IntegrationConfigDto.Response save(@PathVariable("type") String type,
                                              @RequestBody IntegrationConfigDto.SaveRequest body,
                                              Authentication auth) throws JsonProcessingException {
        String normalized = normalizeType(type);
        String configJson = body.config() == null
            ? "{}" : objectMapper.writeValueAsString(body.config());
        String creds = body.credentials() == null ? "" : body.credentials();
        byte[] encrypted = cipher.encrypt(creds);

        IntegrationConfig saved = repository.findByIntegrationType(normalized)
            .map(existing -> {
                existing.setConfigJson(configJson);
                existing.setEncryptedCredentials(encrypted);
                existing.setUpdatedAt(Instant.now());
                return repository.save(existing);
            })
            .orElseGet(() -> repository.save(new IntegrationConfig(normalized, configJson, encrypted)));

        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        auditService.recordEvent(actor, "INTEGRATION_CONFIG_SAVE", "integration_config",
            String.valueOf(saved.getId()), Map.of("type", normalized));

        return IntegrationConfigDto.Response.from(saved);
    }

    /**
     * Pushes the current bundle through the {@code integrationType}'s client.
     * Updates {@code last_push_at} + {@code last_push_status} regardless of outcome.
     */
    @PostMapping("/{type}/push")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<IntegrationConfigDto.PushResponse> push(@PathVariable("type") String type,
                                                                  Authentication auth) {
        String normalized = normalizeType(type);
        IntegrationConfig cfg = repository.findByIntegrationType(normalized)
            .orElseThrow(() -> new NoSuchElementException(
                "integration_config not found for type: " + normalized));
        // Decrypt to verify the saved credentials are still readable (catches corrupted
        // rows + key rotation drift) before we trigger the upstream push. The plaintext
        // itself is intentionally unused — the existing TAXII / MISP clients hold their
        // own env-injected creds; this controller only owns the user-visible config row.
        cipher.decrypt(cfg.getEncryptedCredentials());

        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        Instant now = Instant.now();
        IntegrationConfigDto.PushResponse response;
        try {
            switch (normalized) {
                case TYPE_TAXII -> {
                    Map<String, Object> conf = readConfigMap(cfg.getConfigJson());
                    String collection = conf.get("collectionId") == null
                        ? null : String.valueOf(conf.get("collectionId"));
                    var r = threatIntelService.pushTaxii(collection);
                    cfg.setLastPushAt(now);
                    cfg.setLastPushStatus("SUCCESS: status=" + r.statusCode());
                    response = new IntegrationConfigDto.PushResponse("ok",
                        r.bundleId(), now, cfg.getLastPushStatus());
                }
                case TYPE_MISP -> {
                    var r = threatIntelService.pushMisp();
                    cfg.setLastPushAt(now);
                    cfg.setLastPushStatus("SUCCESS: event=" + r.mispEventId());
                    response = new IntegrationConfigDto.PushResponse("ok",
                        r.bundleId(), now, cfg.getLastPushStatus());
                }
                default -> throw new IllegalArgumentException("unknown integration type: " + normalized);
            }
            auditService.recordEvent(actor,
                TYPE_TAXII.equals(normalized) ? "TAXII_PUSH" : "MISP_PUSH",
                "integration_config", String.valueOf(cfg.getId()),
                Map.of("type", normalized, "status", "SUCCESS"));
        } catch (IOException | RuntimeException e) {
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            String truncated = msg.length() > 200 ? msg.substring(0, 200) : msg;
            cfg.setLastPushAt(now);
            cfg.setLastPushStatus("ERROR: " + truncated);
            auditService.recordEvent(actor,
                TYPE_TAXII.equals(normalized) ? "TAXII_PUSH" : "MISP_PUSH",
                "integration_config", String.valueOf(cfg.getId()),
                Map.of("type", normalized, "status", "ERROR", "message", truncated));
            response = new IntegrationConfigDto.PushResponse("error",
                null, now, cfg.getLastPushStatus());
        } finally {
            cfg.setUpdatedAt(now);
            repository.save(cfg);
        }
        return ResponseEntity.ok(response);
    }

    private String normalizeType(String type) {
        if (type == null) {
            throw new IllegalArgumentException("integration type is required");
        }
        String upper = type.toUpperCase();
        if (!TYPE_TAXII.equals(upper) && !TYPE_MISP.equals(upper)) {
            throw new IllegalArgumentException(
                "unsupported integration type: " + type + " (expected TAXII or MISP)");
        }
        return upper;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readConfigMap(String json) {
        if (json == null || json.isBlank()) return Map.of();
        try {
            return objectMapper.readValue(json, Map.class);
        } catch (JsonProcessingException e) {
            log.warn("integration_config row has unparseable config_json — treating as empty: {}",
                e.getMessage());
            return Map.of();
        }
    }
}

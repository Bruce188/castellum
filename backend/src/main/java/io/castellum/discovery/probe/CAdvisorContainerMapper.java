package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps cAdvisor subcontainer JSON to container names.
 *
 * <p>Parses {@code /api/v1.3/subcontainers} response to extract container names and labels.
 * Malformed entries are skipped (malformed-tolerant).
 */
@Component
public class CAdvisorContainerMapper {

    private static final Logger log = LoggerFactory.getLogger(CAdvisorContainerMapper.class);

    private final ObjectMapper objectMapper;

    public CAdvisorContainerMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Extract container names from cAdvisor subcontainers JSON.
     *
     * @param subcontainersJson JSON from {@code GET /api/v1.3/subcontainers}
     * @return list of container names (malformed-tolerant)
     */
    public List<String> containerNames(String subcontainersJson) {
        List<String> names = new ArrayList<>();
        if (subcontainersJson == null || subcontainersJson.isBlank()) return names;

        try {
            JsonNode root = objectMapper.readTree(subcontainersJson);
            if (!root.isArray()) return names;

            for (JsonNode container : root) {
                try {
                    // Try label first (docker compose service name)
                    JsonNode labels = container.path("labels");
                    String labelName = null;
                    if (labels.isObject()) {
                        JsonNode svcLabel = labels.get("com.docker.compose.service");
                        if (svcLabel != null && svcLabel.isTextual() && !svcLabel.asText().isBlank()) {
                            labelName = svcLabel.asText();
                        }
                    }

                    // Fallback: aliases[0] or name field
                    JsonNode aliases = container.path("aliases");
                    String aliasName = null;
                    if (aliases.isArray() && aliases.size() > 0) {
                        JsonNode first = aliases.get(0);
                        if (first.isTextual() && !first.asText().isBlank()) {
                            aliasName = first.asText();
                        }
                    }

                    String name = labelName != null ? labelName : aliasName;
                    if (name != null && !name.isBlank()) {
                        names.add(name);
                    }
                } catch (Exception e) {
                    log.debug("CAdvisorContainerMapper: malformed container entry — skipping: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            log.debug("CAdvisorContainerMapper: failed to parse subcontainers JSON: {}", e.getMessage());
        }
        return names;
    }
}

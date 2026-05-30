package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps Traefik router/service JSON responses to backend container names.
 *
 * <p>Parses the {@code /api/http/routers} response to extract service names for
 * correlation with the container inventory. Malformed entries are skipped (malformed-tolerant).
 */
@Component
public class TraefikRouterMapper {

    private static final Logger log = LoggerFactory.getLogger(TraefikRouterMapper.class);

    private final ObjectMapper objectMapper;

    public TraefikRouterMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Extract backend service names from Traefik routers + services JSON.
     *
     * @param routersJson JSON from {@code GET /api/http/routers}
     * @param servicesJson JSON from {@code GET /api/http/services} (may be null/empty)
     * @return list of service names referenced by routers (malformed-tolerant)
     */
    public List<String> backendContainerNames(String routersJson, String servicesJson) {
        List<String> names = new ArrayList<>();
        if (routersJson == null || routersJson.isBlank()) return names;

        try {
            JsonNode routers = objectMapper.readTree(routersJson);
            if (!routers.isArray()) return names;

            for (JsonNode router : routers) {
                try {
                    JsonNode serviceNode = router.get("service");
                    if (serviceNode != null && serviceNode.isTextual()) {
                        String svcName = serviceNode.asText();
                        if (!svcName.isBlank()) {
                            names.add(svcName);
                        }
                    }
                } catch (Exception e) {
                    log.debug("TraefikRouterMapper: malformed router entry — skipping: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            log.debug("TraefikRouterMapper: failed to parse routers JSON: {}", e.getMessage());
        }
        return names;
    }
}

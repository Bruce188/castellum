package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.discovery.DockerContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Maps the Docker Engine API {@code GET /networks} JSON response to
 * {@link DockerContainer.DockerNetworkAttachment} values.
 *
 * <p><b>Shape decision:</b> The {@code /networks} endpoint returns a different JSON shape from
 * {@code docker inspect}: networks are top-level objects with {@code IPAM.Config[].Gateway} and
 * a {@code Containers} map keyed by container ID. This mapper extracts the gateway/subnet info
 * per network. Per-container detail (container IP, image, ports) comes from
 * {@code /containers/{id}/json} — the same shape as {@code docker inspect} — which is parsed
 * by the existing {@link io.castellum.discovery.DockerInspectParser}. This approach sidesteps
 * the flatter {@code /containers/json} list shape and reuses the proven parser for full detail.
 *
 * <p>Malformed / blank input is handled gracefully: blank → empty list; non-JSON → throws
 * {@link IllegalArgumentException}; non-array → empty list. Individual network parse errors
 * are skipped with a warning so one bad entry does not abort the whole pass.
 */
@Component
public class DockerApiNetworkMapper {

    private static final Logger log = LoggerFactory.getLogger(DockerApiNetworkMapper.class);

    private final ObjectMapper mapper;

    public DockerApiNetworkMapper() {
        this(new ObjectMapper());
    }

    public DockerApiNetworkMapper(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * Map a {@code GET /networks} response body to a list of network attachments.
     *
     * <p>Each entry in the returned list represents one Docker network's gateway attachment —
     * suitable for the synthetic-gateway upsert in the shared {@code ingest()} path.
     *
     * @param networksJson the raw JSON string from {@code GET /networks}
     * @return list of network attachments (gateway IP + network name); never null
     * @throws IllegalArgumentException if {@code networksJson} is syntactically invalid JSON
     */
    public List<DockerContainer.DockerNetworkAttachment> mapNetworks(String networksJson) {
        List<DockerContainer.DockerNetworkAttachment> out = new ArrayList<>();
        if (networksJson == null || networksJson.isBlank()) {
            return out;
        }
        JsonNode root;
        try {
            root = mapper.readTree(networksJson);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("malformed Docker API /networks JSON: " + e.getOriginalMessage(), e);
        }
        if (root == null || !root.isArray()) {
            return out;
        }
        for (JsonNode net : root) {
            try {
                String name = textOf(net, "Name");
                if (name == null || name.isBlank()) {
                    continue;
                }
                // Extract gateway from IPAM.Config[0].Gateway
                String gateway = null;
                String subnet = null;
                JsonNode ipam = net.path("IPAM");
                JsonNode configs = ipam.path("Config");
                if (configs.isArray() && configs.size() > 0) {
                    JsonNode first = configs.get(0);
                    gateway = textOf(first, "Gateway");
                    subnet = textOf(first, "Subnet");
                }
                if (gateway != null && !gateway.isBlank()) {
                    // containerIp = null for a gateway-only attachment (no container IP at this level)
                    out.add(new DockerContainer.DockerNetworkAttachment(name, null, gateway));
                }
            } catch (Exception e) {
                log.warn("DockerApiNetworkMapper: skipping malformed network entry — {}", e.getMessage());
            }
        }
        return out;
    }

    private static String textOf(JsonNode node, String field) {
        if (node == null) return null;
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) return null;
        return v.asText();
    }
}

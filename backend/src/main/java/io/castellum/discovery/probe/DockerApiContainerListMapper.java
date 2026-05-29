package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps the Docker Engine API {@code GET /containers/json} response to a list of container IDs.
 *
 * <p>The {@code /containers/json} list endpoint returns a flat summary per container. This mapper
 * extracts only the container {@code Id} values. Full container detail (IP, networks, ports,
 * image) is then fetched per-container via {@code GET /containers/{id}/json} and parsed by the
 * existing {@link io.castellum.discovery.DockerInspectParser}, which handles the full inspect
 * shape. This two-phase approach reuses the proven parser and avoids duplicating the complex
 * network-mapping logic for the flatter list shape.
 *
 * <p>Malformed / blank input is handled gracefully: blank → empty list; non-JSON → throws
 * {@link IllegalArgumentException}; non-array → empty list; individual entries without a valid
 * {@code Id} are skipped.
 */
@Component
public class DockerApiContainerListMapper {

    private static final Logger log = LoggerFactory.getLogger(DockerApiContainerListMapper.class);

    private final ObjectMapper mapper;

    public DockerApiContainerListMapper() {
        this(new ObjectMapper());
    }

    public DockerApiContainerListMapper(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * Extract container IDs from a {@code GET /containers/json} response.
     *
     * @param containersListJson the raw JSON string from {@code GET /containers/json}
     * @return list of container ID strings; never null
     * @throws IllegalArgumentException if {@code containersListJson} is syntactically invalid JSON
     */
    public List<String> containerIds(String containersListJson) {
        List<String> ids = new ArrayList<>();
        if (containersListJson == null || containersListJson.isBlank()) {
            return ids;
        }
        JsonNode root;
        try {
            root = mapper.readTree(containersListJson);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("malformed Docker API /containers/json: " + e.getOriginalMessage(), e);
        }
        if (root == null || !root.isArray()) {
            return ids;
        }
        for (JsonNode entry : root) {
            try {
                JsonNode idNode = entry.get("Id");
                if (idNode != null && !idNode.isNull()) {
                    String id = idNode.asText();
                    if (!id.isBlank()) {
                        ids.add(id);
                    }
                }
            } catch (Exception e) {
                log.warn("DockerApiContainerListMapper: skipping malformed container entry — {}", e.getMessage());
            }
        }
        return ids;
    }
}

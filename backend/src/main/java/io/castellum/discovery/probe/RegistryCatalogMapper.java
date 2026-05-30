package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps Docker Registry v2 catalog and tag responses into host-metadata blobs.
 *
 * <p><b>R6 invariant:</b> the registry catalog is stored as a compact, delimited string on the
 * probed host's {@code device.registry_images} column — NOT as per-image topology rows or Device
 * entities. The blob is informational host metadata only.
 *
 * <p>Malformed-tolerant: any JSON parse error returns an empty list/blob without throwing.
 * Repository count is capped at {@link DockerHostProbeService#MAX_CONTAINERS_PER_HOST} to bound
 * untrusted input.
 *
 * <p><b>Blob format:</b> a newline-delimited list of repository names (optionally suffixed with
 * tags in {@code name:tag} form if tags are fetched). For simplicity, this mapper stores bare
 * repository names as a comma-separated string, e.g. {@code "nginx,redis,myapp"}.
 */
@Component
public class RegistryCatalogMapper {

    private static final Logger log = LoggerFactory.getLogger(RegistryCatalogMapper.class);

    private final ObjectMapper objectMapper;

    public RegistryCatalogMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Parse the {@code /v2/_catalog} JSON response into a list of repository names.
     *
     * @param catalogJson the raw catalog JSON (e.g. {@code {"repositories":["nginx","redis"]}})
     * @return list of repository names (empty on malformed/blank input)
     */
    public List<String> repositories(String catalogJson) {
        if (catalogJson == null || catalogJson.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(catalogJson);
            JsonNode repos = root.path("repositories");
            if (!repos.isArray()) {
                log.debug("RegistryCatalogMapper: 'repositories' is not an array");
                return List.of();
            }
            List<String> result = new ArrayList<>();
            for (JsonNode repo : repos) {
                if (result.size() >= DockerHostProbeService.MAX_CONTAINERS_PER_HOST) {
                    log.warn("RegistryCatalogMapper: repo count cap {} reached — truncating",
                        DockerHostProbeService.MAX_CONTAINERS_PER_HOST);
                    break;
                }
                String name = repo.asText(null);
                if (name != null && !name.isBlank()) {
                    result.add(name);
                }
            }
            return result;
        } catch (Exception e) {
            log.debug("RegistryCatalogMapper: malformed catalog JSON — returning empty list: {}", e.getMessage());
            return List.of();
        }
    }

    /**
     * Parse the {@code /v2/{name}/tags/list} JSON response into a list of tag strings.
     *
     * @param tagsJson the raw tags JSON (e.g. {@code {"name":"nginx","tags":["latest","1.25"]}})
     * @return list of tag strings (empty on malformed/blank input)
     */
    public List<String> tags(String tagsJson) {
        if (tagsJson == null || tagsJson.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(tagsJson);
            JsonNode tagsArray = root.path("tags");
            if (!tagsArray.isArray()) {
                return List.of();
            }
            List<String> result = new ArrayList<>();
            for (JsonNode tag : tagsArray) {
                String t = tag.asText(null);
                if (t != null && !t.isBlank()) {
                    result.add(t);
                }
            }
            return result;
        } catch (Exception e) {
            log.debug("RegistryCatalogMapper: malformed tags JSON — returning empty list: {}", e.getMessage());
            return List.of();
        }
    }

    /**
     * Fold a list of repository names into the compact {@code registry_images} blob persisted
     * on the device row.
     *
     * <p>Format: comma-separated repository names, e.g. {@code "nginx,redis,myapp"}.
     * An empty list produces an empty string.
     *
     * @param repos the list of repository names
     * @return the compact blob string
     */
    public String toInventoryBlob(List<String> repos) {
        if (repos == null || repos.isEmpty()) {
            return "";
        }
        return String.join(",", repos);
    }
}

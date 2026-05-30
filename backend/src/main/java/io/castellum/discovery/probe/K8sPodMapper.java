package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.discovery.DockerContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps a Kubernetes/kubelet {@code PodList} JSON response into a list of {@link DockerContainer}s
 * so the shared {@link io.castellum.discovery.DockerDiscoveryService#ingest} path can attribute
 * pod topology to the probed host.
 *
 * <p><b>Design decisions (R7):</b>
 * <ul>
 *   <li>Pods are mapped as {@link DockerContainer}s reusing {@code DiscoverySource.DOCKER} —
 *       no new DiscoverySource value is needed. Rule 2 of the classifier maps DOCKER-sourced
 *       devices to {@code CONTAINER} at HIGH confidence, distinct from the macvlan LOW heuristic.</li>
 *   <li>Each pod becomes one {@link DockerContainer} with a single synthetic
 *       {@link DockerContainer.DockerNetworkAttachment} carrying the pod IP.</li>
 *   <li>Malformed-tolerant: any pod entry missing a {@code status.podIP} is silently skipped.
 *       A completely malformed JSON payload returns an empty list without throwing.</li>
 *   <li>Pod count is capped at {@link DockerHostProbeService#MAX_CONTAINERS_PER_HOST} to bound
 *       untrusted input.</li>
 * </ul>
 */
@Component
public class K8sPodMapper {

    private static final Logger log = LoggerFactory.getLogger(K8sPodMapper.class);

    private final ObjectMapper objectMapper;

    public K8sPodMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Map a {@code PodList} JSON string to a list of {@link DockerContainer}s.
     *
     * @param podListJson the raw {@code PodList} JSON from the k8s/kubelet API
     * @return a list of mapped containers (empty on malformed input or no usable pods)
     */
    public List<DockerContainer> mapPods(String podListJson) {
        if (podListJson == null || podListJson.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(podListJson);
            JsonNode items = root.path("items");
            if (!items.isArray()) {
                log.debug("K8sPodMapper: 'items' is not an array — returning empty list");
                return List.of();
            }
            List<DockerContainer> result = new ArrayList<>();
            for (JsonNode item : items) {
                if (result.size() >= DockerHostProbeService.MAX_CONTAINERS_PER_HOST) {
                    log.warn("K8sPodMapper: pod count cap {} reached — truncating",
                        DockerHostProbeService.MAX_CONTAINERS_PER_HOST);
                    break;
                }
                try {
                    DockerContainer c = mapPod(item);
                    if (c != null) {
                        result.add(c);
                    }
                } catch (Exception e) {
                    log.debug("K8sPodMapper: skipping malformed pod entry: {}", e.getMessage());
                }
            }
            return result;
        } catch (Exception e) {
            log.debug("K8sPodMapper: malformed PodList JSON — returning empty list: {}", e.getMessage());
            return List.of();
        }
    }

    private DockerContainer mapPod(JsonNode item) {
        // Extract pod IP — skip pods without a usable IP
        JsonNode statusNode = item.path("status");
        String podIp = statusNode.path("podIP").asText(null);
        if (podIp == null || podIp.isBlank() || "null".equals(podIp)) {
            return null; // skipped
        }

        // name: metadata.name (use uid as id, name as hostname)
        JsonNode metaNode = item.path("metadata");
        String name = metaNode.path("name").asText("unknown-pod");
        String uid = metaNode.path("uid").asText(name);

        // image: first container image in spec.containers[]
        String image = null;
        JsonNode containers = item.path("spec").path("containers");
        if (containers.isArray() && containers.size() > 0) {
            image = containers.get(0).path("image").asText(null);
        }

        // Build a single synthetic network attachment using the pod IP
        DockerContainer.DockerNetworkAttachment attachment =
            new DockerContainer.DockerNetworkAttachment("pod-network", podIp, null);

        return new DockerContainer(
            uid,
            name,
            image,
            List.of(attachment),
            false,
            List.of()
        );
    }
}

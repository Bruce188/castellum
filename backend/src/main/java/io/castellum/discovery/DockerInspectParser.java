package io.castellum.discovery;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Pure parser for {@code docker inspect <ids...>} JSON output. Stateless and free of any
 * process spawning so it can be unit-tested against hand-authored fixtures.
 *
 * <p>{@code docker inspect} emits a JSON array; each element is one container with (the subset
 * Castellum reads):
 * <pre>
 * {
 *   "Id": "abc123…",
 *   "Name": "/pingpay-frontend",
 *   "NetworkSettings": {
 *     "Ports": { "80/tcp": [ { "HostIp": "0.0.0.0", "HostPort": "1071" } ], "443/tcp": null },
 *     "Networks": {
 *       "pingpay_default": { "IPAddress": "172.18.0.4", "Gateway": "172.18.0.1" }
 *     }
 *   }
 * }
 * </pre>
 *
 * <p>A container "publishes a host port" iff any {@code NetworkSettings.Ports} entry has a
 * non-null binding array containing at least one entry with a non-blank {@code HostPort}.
 * Unpublished (internal-only) ports map to {@code null} and are ignored.
 */
@Component
public class DockerInspectParser {

    private final ObjectMapper mapper;

    public DockerInspectParser() {
        this(new ObjectMapper());
    }

    /** Injectable constructor for tests / shared mapper reuse. */
    public DockerInspectParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * Parse the full {@code docker inspect} array.
     *
     * @param json raw stdout from {@code docker inspect}; may be empty/blank
     * @return one {@link DockerContainer} per array element with a usable name; never null
     */
    public List<DockerContainer> parse(String json) {
        List<DockerContainer> out = new ArrayList<>();
        if (json == null || json.isBlank()) {
            return out;
        }
        JsonNode root;
        try {
            root = mapper.readTree(json);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("malformed docker inspect JSON: " + e.getOriginalMessage(), e);
        }
        if (root == null || !root.isArray()) {
            return out;
        }
        for (JsonNode node : root) {
            DockerContainer c = parseOne(node);
            if (c != null) {
                out.add(c);
            }
        }
        return out;
    }

    private DockerContainer parseOne(JsonNode node) {
        if (node == null || !node.isObject()) {
            return null;
        }
        String name = cleanName(text(node, "Name"));
        if (name == null || name.isBlank()) {
            return null; // un-named element — nothing to upsert against
        }
        String id = text(node, "Id");

        JsonNode netSettings = node.path("NetworkSettings");
        List<DockerContainer.DockerNetworkAttachment> nets = parseNetworks(netSettings.path("Networks"));
        boolean publishes = anyPublishedPort(netSettings.path("Ports"));

        return new DockerContainer(id, name, nets, publishes);
    }

    private List<DockerContainer.DockerNetworkAttachment> parseNetworks(JsonNode networks) {
        List<DockerContainer.DockerNetworkAttachment> out = new ArrayList<>();
        if (networks == null || !networks.isObject()) {
            return out;
        }
        Iterator<Map.Entry<String, JsonNode>> it = networks.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> entry = it.next();
            String networkName = entry.getKey();
            JsonNode net = entry.getValue();
            String ip = text(net, "IPAddress");
            String gw = text(net, "Gateway");
            out.add(new DockerContainer.DockerNetworkAttachment(networkName, ip, gw));
        }
        return out;
    }

    /**
     * True iff any port entry has a non-null binding list with a non-blank {@code HostPort}.
     * The {@code Ports} object maps {@code "<port>/<proto>"} → array-of-bindings | null.
     */
    private boolean anyPublishedPort(JsonNode ports) {
        if (ports == null || !ports.isObject()) {
            return false;
        }
        Iterator<Map.Entry<String, JsonNode>> it = ports.fields();
        while (it.hasNext()) {
            JsonNode bindings = it.next().getValue();
            if (bindings == null || !bindings.isArray()) {
                continue; // null = internal-only port
            }
            for (JsonNode binding : bindings) {
                String hostPort = text(binding, "HostPort");
                if (hostPort != null && !hostPort.isBlank()) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Container names arrive with a leading slash (e.g. {@code /pingpay-db}); strip it. */
    private static String cleanName(String raw) {
        if (raw == null) {
            return null;
        }
        String t = raw.trim();
        return t.startsWith("/") ? t.substring(1) : t;
    }

    /** Null-safe textual field read; returns {@code null} for missing/null nodes. */
    private static String text(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        return v.asText();
    }
}

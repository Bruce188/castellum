package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Fingerprints port 8080 to distinguish Traefik from cAdvisor from unknown services (R3).
 *
 * <p>Port 8080 is shared by both Traefik (dashboard API) and cAdvisor (metrics). This class
 * probes the port to determine which service is present, so the correct probe path is taken
 * and no assumptions are made.
 *
 * <p>Fingerprint logic:
 * <ol>
 *   <li>GET /api/overview → if Traefik-shaped (has "http" key with "routers"/"services") → TRAEFIK</li>
 *   <li>GET /api/v1.3/machine → if cAdvisor-shaped (has "num_cores" or "memory_capacity") → CADVISOR</li>
 *   <li>Otherwise → UNKNOWN (no extraction, no finding)</li>
 * </ol>
 *
 * <p>UNKNOWN → no extraction and no finding. This is the required disambiguation (R3).
 */
@Component
public class Port8080Fingerprinter {

    private static final Logger log = LoggerFactory.getLogger(Port8080Fingerprinter.class);

    /** Result of port 8080 fingerprinting. */
    public enum Identity {
        TRAEFIK,
        CADVISOR,
        UNKNOWN
    }

    private final TraefikApiClient traefikClient;
    private final CAdvisorApiClient cadvisorClient;
    private final ObjectMapper objectMapper;

    public Port8080Fingerprinter(TraefikApiClient traefikClient,
                                 CAdvisorApiClient cadvisorClient,
                                 ObjectMapper objectMapper) {
        this.traefikClient = traefikClient;
        this.cadvisorClient = cadvisorClient;
        this.objectMapper = objectMapper;
    }

    /**
     * Identify the service on the given host:port.
     *
     * @param host target host IP
     * @param port target port (typically 8080)
     * @return TRAEFIK, CADVISOR, or UNKNOWN (never assume — R3)
     */
    public Identity identify(String host, int port) {
        // Try Traefik: GET /api/overview → Traefik-shaped response
        Optional<String> overviewOpt = traefikClient.getOverview(host, port);
        if (overviewOpt.isPresent() && isTraefikShaped(overviewOpt.get())) {
            log.debug("Port8080Fingerprinter: {}:{} identified as TRAEFIK", host, port);
            return Identity.TRAEFIK;
        }

        // Try cAdvisor: GET /api/v1.3/machine → cAdvisor-shaped response
        Optional<String> machineOpt = cadvisorClient.getMachine(host, port);
        if (machineOpt.isPresent() && isCAdvisorShaped(machineOpt.get())) {
            log.debug("Port8080Fingerprinter: {}:{} identified as CADVISOR", host, port);
            return Identity.CADVISOR;
        }

        log.debug("Port8080Fingerprinter: {}:{} is UNKNOWN — no extraction, no finding (R3)", host, port);
        return Identity.UNKNOWN;
    }

    /** Returns true if the JSON has a Traefik overview shape (has "http" with router/service stats). */
    private boolean isTraefikShaped(String json) {
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode http = root.get("http");
            if (http == null || !http.isObject()) return false;
            return http.has("routers") || http.has("services");
        } catch (Exception e) {
            return false;
        }
    }

    /** Returns true if the JSON has a cAdvisor machine shape (has num_cores or memory_capacity). */
    private boolean isCAdvisorShaped(String json) {
        try {
            JsonNode root = objectMapper.readTree(json);
            return root.has("num_cores") || root.has("memory_capacity");
        } catch (Exception e) {
            return false;
        }
    }
}

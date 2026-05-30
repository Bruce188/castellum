package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DockerContainer;
import io.castellum.discovery.DockerDiscoveryResponse;
import io.castellum.discovery.DockerDiscoveryService;
import io.castellum.discovery.DockerInspectParser;
import io.castellum.discovery.OriginContext;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.util.List;
import java.util.Map;

/**
 * Accepts push-based Docker discovery payloads from remote agents.
 *
 * <p>Route auth is enforced by {@link io.castellum.security.RemoteAgentTokenAuthFilter}
 * (ROLE_REMOTE_AGENT principal) — NO class-level {@code @PreAuthorize} here.
 * JWT chain and existing ADMIN endpoints are untouched.
 *
 * <p><b>Security invariants:</b>
 * <ul>
 *   <li>The bearer token is NEVER echoed, logged, or included in any response or audit detail.</li>
 *   <li>The {@code containers} payload is size-bounded by Bean Validation AND by an explicit
 *       in-controller byte cap BEFORE the parser is invoked. Oversized → 4xx; parse not called.</li>
 *   <li>Malformed JSON in {@code containers} → {@link IllegalArgumentException} caught by
 *       {@link GlobalExceptionHandler} → 4xx (NOT 500).</li>
 * </ul>
 */
@RestController
public class RemoteDockerController {

    /** Hard byte cap on the containers JSON string enforced before the parser is invoked. */
    static final int CONTAINERS_MAX_BYTES = 2_000_000;

    private final DockerDiscoveryService dockerDiscoveryService;
    private final DockerInspectParser dockerInspectParser;
    private final AuditService auditService;
    private final Clock clock;

    public RemoteDockerController(DockerDiscoveryService dockerDiscoveryService,
                                  DockerInspectParser dockerInspectParser,
                                  AuditService auditService,
                                  Clock clock) {
        this.dockerDiscoveryService = dockerDiscoveryService;
        this.dockerInspectParser = dockerInspectParser;
        this.auditService = auditService;
        this.clock = clock;
    }

    /**
     * Accepts a push payload from a remote agent and delegates to the shared ingest path.
     *
     * <p>The agent's {@code Authorization: Bearer <token>} header is verified by
     * {@link io.castellum.security.RemoteAgentTokenAuthFilter} before this method is reached.
     *
     * @param req validated ingest request
     * @return 200 with upsert counts
     */
    @PostMapping("/api/discovery/remote-docker")
    public ResponseEntity<DockerDiscoveryResponse> ingest(@Valid @RequestBody RemoteDockerIngestRequest req) {
        // In-controller size cap BEFORE parse — defence-in-depth on top of @Size validation.
        if (req.containers() != null && req.containers().length() > CONTAINERS_MAX_BYTES) {
            throw new IllegalArgumentException("containers payload exceeds maximum allowed size");
        }

        List<DockerContainer> containers = dockerInspectParser.parse(req.containers());

        OriginContext origin = OriginContext.of(req.primaryIp(), req.hostname());
        DockerDiscoveryResponse result = dockerDiscoveryService.ingest(containers, origin, clock.instant());

        // Audit: NO token value or validity in detail
        auditService.recordEvent(
                req.agentId(),
                "REMOTE_DOCKER_INGEST",
                "discovery",
                req.agentId(),
                Map.of("hostname", String.valueOf(req.hostname()),
                       "containerCount", containers.size()));

        return ResponseEntity.ok(result);
    }
}

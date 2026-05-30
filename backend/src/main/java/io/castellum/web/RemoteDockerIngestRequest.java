package io.castellum.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Validated request DTO for {@code POST /api/discovery/remote-docker}.
 *
 * <p>All size constraints are enforced by Bean Validation before the controller body runs,
 * mapping to 4xx via {@link GlobalExceptionHandler}.
 *
 * @param agentId    stable ID for the agent (e.g. hostname-derived); used in audit rows
 * @param hostname   human-readable hostname of the remote host (optional but recommended)
 * @param primaryIp  first non-loopback IPv4 of the remote host (required — used as origin key)
 * @param osHint     optional OS hint string passed to device-role classification
 * @param containers verbatim {@code docker inspect} JSON array string; size-bounded here
 *                   AND by an explicit in-controller cap before the parser is invoked
 */
public record RemoteDockerIngestRequest(
        @NotBlank @Size(max = 128) String agentId,
        @Size(max = 255) String hostname,
        @NotBlank @Size(max = 64) String primaryIp,
        @Size(max = 255) String osHint,
        @NotBlank @Size(max = 2_000_000) String containers
) {}

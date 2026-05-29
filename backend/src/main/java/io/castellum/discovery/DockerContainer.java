package io.castellum.discovery;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * A single running container as extracted from {@code docker inspect} JSON.
 *
 * <p>Only the fields Castellum needs for topology rendering + service/CVE correlation are
 * modelled:
 * <ul>
 *   <li>{@code name} — the container name (leading {@code /} stripped), used as the
 *       device hostname.</li>
 *   <li>{@code image} — the {@code Config.Image} reference (e.g. {@code postgres:16}); drives the
 *       image→CPE service derivation in {@link DockerImageCpe}. May be {@code null}.</li>
 *   <li>{@code networks} — the container's attachment(s); each carries the docker network
 *       name, the container's IP on that network, and that network's gateway IP. The
 *       <em>primary</em> network (first non-blank-IP attachment) supplies the device IP.</li>
 *   <li>{@code publishesHostPort} — true iff any port has a non-empty {@code HostPort}
 *       binding. Parsed but currently unused (scope is no longer derived from it — all
 *       discovered containers receive {@link DiscoveryScope#DOCKER_BRIDGE} unconditionally).</li>
 *   <li>{@code exposedPorts} — the {@code NetworkSettings.Ports} keys parsed to (port, protocol).
 *       The lowest-numbered one ({@link #primaryPort()}) keys the container's service row.</li>
 * </ul>
 */
public record DockerContainer(
    String id,
    String name,
    String image,
    List<DockerNetworkAttachment> networks,
    boolean publishesHostPort,
    List<ExposedPort> exposedPorts
) {
    public DockerContainer {
        Objects.requireNonNull(name, "name must not be null");
        networks = networks == null ? List.of() : List.copyOf(networks);
        exposedPorts = exposedPorts == null ? List.of() : List.copyOf(exposedPorts);
    }

    /**
     * The container's primary network attachment — the first attachment with a non-blank
     * container IP. Compose stacks usually attach a container to exactly one user-defined
     * bridge; multi-homed containers pick their first usable address deterministically.
     *
     * @return the primary attachment, or {@code null} if no attachment has a usable IP
     */
    public DockerNetworkAttachment primaryNetwork() {
        for (DockerNetworkAttachment n : networks) {
            if (n.containerIp() != null && !n.containerIp().isBlank()) {
                return n;
            }
        }
        return null;
    }

    /**
     * The container's primary service port — the lowest-numbered exposed port. Deterministic so a
     * container's service row is keyed stably across re-runs (e.g. postgres → 5432). Both
     * published and internal-only ports are candidates; the port describes what the container
     * listens on regardless of host publishing.
     *
     * @return the lowest exposed port, or {@code null} if the container exposes none
     */
    public ExposedPort primaryPort() {
        return exposedPorts.stream()
            .min(Comparator.comparingInt(ExposedPort::port))
            .orElse(null);
    }

    /** A container's membership of one docker network. */
    public record DockerNetworkAttachment(
        String networkName,
        String containerIp,
        String gatewayIp
    ) {}

    /** A container port exposed in {@code NetworkSettings.Ports} (published or internal-only). */
    public record ExposedPort(int port, String protocol) {}
}

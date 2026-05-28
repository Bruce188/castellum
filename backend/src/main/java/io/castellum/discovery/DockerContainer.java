package io.castellum.discovery;

import java.util.List;
import java.util.Objects;

/**
 * A single running container as extracted from {@code docker inspect} JSON.
 *
 * <p>Only the fields Castellum needs for topology rendering are modelled:
 * <ul>
 *   <li>{@code name} — the container name (leading {@code /} stripped), used as the
 *       device hostname.</li>
 *   <li>{@code networks} — the container's attachment(s); each carries the docker network
 *       name, the container's IP on that network, and that network's gateway IP. The
 *       <em>primary</em> network (first non-blank-IP attachment) supplies the device IP.</li>
 *   <li>{@code publishesHostPort} — true iff any port has a non-empty {@code HostPort}
 *       binding. Drives the {@link DiscoveryScope} mapping (DOCKER_BRIDGE vs HOME).</li>
 * </ul>
 */
public record DockerContainer(
    String id,
    String name,
    List<DockerNetworkAttachment> networks,
    boolean publishesHostPort
) {
    public DockerContainer {
        Objects.requireNonNull(name, "name must not be null");
        networks = networks == null ? List.of() : List.copyOf(networks);
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

    /** A container's membership of one docker network. */
    public record DockerNetworkAttachment(
        String networkName,
        String containerIp,
        String gatewayIp
    ) {}
}

package io.castellum.web.dto;

/**
 * Read-only DTO for {@code GET /api/discovery/interfaces}. Reports the up,
 * non-loopback network interfaces visible to the JVM so an ADMIN can pick
 * which interface a passive sweep should bind to.
 *
 * <p>Sourced from {@link java.net.NetworkInterface#getNetworkInterfaces()};
 * filtered to {@code isUp() && !isLoopback()}.
 */
public record InterfaceInfoDto(
    String name,
    String displayName,
    int mtu
) {}

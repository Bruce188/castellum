package io.castellum.web.dto;

/**
 * Read-only DTO for {@code GET /api/discovery/interfaces}. Reports the up,
 * non-loopback network interfaces visible to the JVM so an ADMIN can pick
 * which interface a passive sweep should bind to.
 *
 * <p>Sourced from {@link java.net.NetworkInterface#getNetworkInterfaces()};
 * filtered to {@code isUp() && !isLoopback()}.
 *
 * <p>{@code ipAddress} is the first IPv4 address bound to the interface, or
 * {@code null} when none is found. {@code prefix} is the network prefix length
 * of that address (e.g. 22 for a /22), or {@code 0} when unknown.
 */
public record InterfaceInfoDto(
    String name,
    String displayName,
    int mtu,
    /** First IPv4 address on this interface, or {@code null} when none is assigned. */
    String ipAddress,
    /** Network prefix length of {@code ipAddress}, or {@code 0} when unknown. */
    int prefix
) {}

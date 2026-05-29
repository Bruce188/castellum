package io.castellum.discovery;

/**
 * Value carrying the origin of a remote discovery observation — the IP address and optional
 * hostname of the host from which devices were discovered (e.g. a probed Docker daemon host).
 *
 * <p>The canonical local-discovery value is {@link #local()}: {@code originHostIp="local"},
 * {@code originHostName=null}. All ARP/NMAP/Docker-CLI/passive paths pass {@code local()} so
 * their dedup semantics are byte-identical to the pre-V27 single-column uniqueness.
 *
 * <p>A remote probe (Phase 4) creates an instance via {@link #of(String, String)} with the
 * probed host's IP and hostname, allowing two hosts that share an internal subnet (e.g.
 * both assigning 172.17.0.2 on their docker0 bridge) to coexist as separate device rows under
 * the composite {@code UNIQUE(ip_address, origin_host_ip)} constraint.
 *
 * @param originHostIp   IP of the discovering host. Never null; {@code "local"} for local discovery.
 * @param originHostName Human-readable hostname of the discovering host. Null for local discovery
 *                       and when unknown at probe time.
 */
public record OriginContext(String originHostIp, String originHostName) {

    /** Canonical local-discovery origin: originHostIp="local", originHostName=null. */
    public static OriginContext local() {
        return new OriginContext("local", null);
    }

    /**
     * Remote-probe origin.
     *
     * @param ip   IP of the probed host (never null)
     * @param name hostname of the probed host (may be null if unknown)
     */
    public static OriginContext of(String ip, String name) {
        if (ip == null) throw new IllegalArgumentException("originHostIp must not be null");
        return new OriginContext(ip, name);
    }
}

package io.castellum.discovery.probe;

/**
 * Value type carrying a host address and TCP port for reachability probing.
 *
 * <p>Used as the argument type for the injected {@code Predicate<HostPort> reachable}
 * seam so tests can control TCP-connect outcomes without real sockets.
 *
 * @param host the host IP address string
 * @param port the TCP port number
 */
public record HostPort(String host, int port) {}

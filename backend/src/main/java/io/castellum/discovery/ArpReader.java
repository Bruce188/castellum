package io.castellum.discovery;

import java.util.List;

/**
 * Cross-platform ARP cache reader contract. Concrete implementations:
 * <ul>
 *   <li>{@link LinuxArpReader} — reads {@code /proc/net/arp}.</li>
 *   <li>{@code WindowsArpReader} — shells out to {@code arp -a} (Phase B.2).</li>
 *   <li>{@code MacArpReader} — shells out to {@code arp -an} (Phase B.3).</li>
 * </ul>
 *
 * <p>Selection is delegated to {@link ArpReaderFactory} based on {@code os.name}.
 * Implementations should return an empty list (not throw) when the host has no ARP table —
 * isolated CI containers and freshly-booted nodes are valid empty-cache scenarios.
 *
 * @see ArpReaderFactory
 */
public interface ArpReader {

    /**
     * Reads the host ARP cache.
     *
     * @return discovered neighbors; never {@code null}.
     * @throws DiscoveryUnavailableException when the underlying source is unreachable
     *         (e.g. {@code arp} binary missing, process spawn failure). Does NOT throw
     *         when the cache is simply empty.
     */
    List<DiscoveredNeighbor> read() throws DiscoveryUnavailableException;
}

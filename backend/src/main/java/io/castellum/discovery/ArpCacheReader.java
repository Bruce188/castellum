package io.castellum.discovery;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Backwards-compatibility façade over {@link LinuxArpReader}. Older code paths
 * (notably {@code PassiveDiscoveryService}) inject this class directly — Phase B.4
 * replaces those direct injections with {@link ArpReaderFactory#select()}.
 *
 * <p>This façade preserves the {@code @Service} bean name so callers that have not
 * yet migrated continue to work; new callers should depend on {@link ArpReader} or
 * {@link ArpReaderFactory}.
 */
@Service
public class ArpCacheReader implements ArpReader {

    private final ArpReader delegate;

    @Autowired
    public ArpCacheReader(LinuxArpReader delegate) {
        this.delegate = delegate;
    }

    /** Test-only constructor that builds a fresh {@link LinuxArpReader} pointing at {@code procPath}. */
    public ArpCacheReader(String procPath) {
        this(new LinuxArpReader(procPath));
    }

    @Override
    public List<DiscoveredNeighbor> read() throws DiscoveryUnavailableException {
        return delegate.read();
    }
}

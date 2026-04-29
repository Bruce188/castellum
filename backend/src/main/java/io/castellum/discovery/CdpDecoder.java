package io.castellum.discovery;

import org.springframework.stereotype.Service;

import java.util.List;

/**
 * CDP (Cisco Discovery Protocol) frame decoder.
 *
 * @implNote UNTESTED — requires Cisco-equivalent switch advertising CDP frames.
 *           The project does not currently own such infrastructure.
 *           Enabling this path without first writing a fixture-replay test
 *           against captured CDP frames is undefined behavior.
 *           Feature flag: <code>castellum.discovery.cdp.enabled</code> (default false).
 */
@Service
public class CdpDecoder {

    public List<DiscoveredNeighbor> decode(byte[] frame) {
        throw new UnsupportedOperationException(
            "CDP decoder is designed-but-untested — requires Cisco-equivalent switch infrastructure. "
            + "Set castellum.discovery.cdp.enabled=true and provide a tested fixture before enabling.");
    }
}

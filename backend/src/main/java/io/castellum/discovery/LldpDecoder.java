package io.castellum.discovery;

import org.springframework.stereotype.Service;

import java.util.List;

/**
 * LLDP frame decoder.
 *
 * @implNote UNTESTED — requires managed switch advertising LLDP-MED frames.
 *           The project does not currently own such infrastructure.
 *           Enabling this path without first writing a fixture-replay test
 *           against captured LLDP frames is undefined behavior.
 *           Feature flag: <code>castellum.discovery.lldp.enabled</code> (default false).
 */
@Service
public class LldpDecoder {

    public List<DiscoveredNeighbor> decode(byte[] frame) {
        throw new UnsupportedOperationException(
            "LLDP decoder is designed-but-untested — requires managed switch infrastructure. "
            + "Set castellum.discovery.lldp.enabled=true and provide a tested fixture before enabling.");
    }
}

package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.pcap4j.core.PcapNetworkInterface;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JvmFlagsSmokeTest {

    @Test
    void ac2_pcap4jJvmFlagsAreApplied() throws Exception {
        // Pcaps.findAllDevs() triggers JNA reflective access into sun.nio.ch.
        // Without --enable-native-access=ALL-UNNAMED and --add-opens java.base/sun.nio.ch=ALL-UNNAMED,
        // this throws IllegalAccessError immediately.
        // findAllDevs() does NOT require CAP_NET_RAW (enumeration only).
        List<PcapNetworkInterface> devs = org.pcap4j.core.Pcaps.findAllDevs();
        assertThat(devs).isNotNull();
    }
}

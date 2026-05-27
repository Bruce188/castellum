package io.castellum.graph;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GraphPropertiesTest {

    @Test
    void dockerHostIpDefaultIs192168_68_51() {
        assertThat(new GraphProperties().getDockerHostIp()).isEqualTo("192.168.68.51");
    }

    @Test
    void dockerHostIpRoundTrip() {
        GraphProperties p = new GraphProperties();
        p.setDockerHostIp("10.0.0.1");
        assertThat(p.getDockerHostIp()).isEqualTo("10.0.0.1");
    }
}

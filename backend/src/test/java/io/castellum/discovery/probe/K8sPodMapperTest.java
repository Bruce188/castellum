package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.discovery.DockerContainer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link K8sPodMapper}.
 */
class K8sPodMapperTest {

    private static final ObjectMapper OM = new ObjectMapper();
    private static final K8sPodMapper MAPPER = new K8sPodMapper(OM);

    private static String fixture(String name) throws IOException {
        try (InputStream in = K8sPodMapperTest.class.getResourceAsStream("/k8s/" + name)) {
            if (in == null) throw new IOException("fixture /k8s/" + name + " not found");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void mapPods_k8sPodList_returnsCorrectContainers() throws Exception {
        String json = fixture("k8s-pods.json");
        List<DockerContainer> result = MAPPER.mapPods(json);

        assertThat(result).hasSize(2);
        DockerContainer first = result.get(0);
        assertThat(first.name()).isEqualTo("nginx-deployment-abc12");
        assertThat(first.image()).isEqualTo("nginx:1.25");
        assertThat(first.primaryNetwork()).isNotNull();
        assertThat(first.primaryNetwork().containerIp()).isEqualTo("10.244.0.5");

        DockerContainer second = result.get(1);
        assertThat(second.name()).isEqualTo("redis-pod-xyz99");
        assertThat(second.image()).isEqualTo("redis:7.0");
        assertThat(second.primaryNetwork().containerIp()).isEqualTo("10.244.0.6");
    }

    @Test
    void mapPods_kubeletPodList_returnsCorrectContainers() throws Exception {
        String json = fixture("kubelet-pods.json");
        List<DockerContainer> result = MAPPER.mapPods(json);

        assertThat(result).hasSize(1);
        DockerContainer pod = result.get(0);
        assertThat(pod.name()).isEqualTo("coredns-abc");
        assertThat(pod.image()).isEqualTo("registry.k8s.io/coredns/coredns:v1.10.1");
        assertThat(pod.primaryNetwork().containerIp()).isEqualTo("10.244.0.2");
    }

    @Test
    void mapPods_malformedJson_returnsEmptyList() {
        List<DockerContainer> result = MAPPER.mapPods("{not valid json{{");
        assertThat(result).isEmpty();
    }

    @Test
    void mapPods_blankInput_returnsEmptyList() {
        assertThat(MAPPER.mapPods("")).isEmpty();
        assertThat(MAPPER.mapPods(null)).isEmpty();
        assertThat(MAPPER.mapPods("   ")).isEmpty();
    }

    @Test
    void mapPods_podMissingPodIp_skipped() {
        String json = """
            {
              "items": [
                {
                  "metadata": { "name": "no-ip-pod", "uid": "uid-001" },
                  "spec": { "containers": [{ "image": "nginx" }] },
                  "status": {}
                },
                {
                  "metadata": { "name": "valid-pod", "uid": "uid-002" },
                  "spec": { "containers": [{ "image": "redis" }] },
                  "status": { "podIP": "10.0.0.5" }
                }
              ]
            }
            """;
        List<DockerContainer> result = MAPPER.mapPods(json);
        assertThat(result).hasSize(1);
        assertThat(result.get(0).name()).isEqualTo("valid-pod");
    }

    @Test
    void mapPods_overCapPodCount_truncated() {
        // Build a PodList with MAX_CONTAINERS_PER_HOST + 1 entries
        int cap = DockerHostProbeService.MAX_CONTAINERS_PER_HOST;
        StringBuilder sb = new StringBuilder("{\"items\":[");
        for (int i = 0; i <= cap; i++) {
            if (i > 0) sb.append(",");
            sb.append("""
                {"metadata":{"name":"pod-%d","uid":"uid-%d"},
                 "spec":{"containers":[{"image":"nginx"}]},
                 "status":{"podIP":"10.0.%d.%d"}}
                """.formatted(i, i, (i / 256) % 256, i % 256));
        }
        sb.append("]}");
        List<DockerContainer> result = MAPPER.mapPods(sb.toString());
        assertThat(result).hasSize(cap);
    }
}

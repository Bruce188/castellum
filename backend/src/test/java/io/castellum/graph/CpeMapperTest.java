package io.castellum.graph;

import io.castellum.domain.NetworkService;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class CpeMapperTest {

    private static NetworkService svc(String name, String version) {
        return new NetworkService(null, 1L, 22, "tcp", name, version, Instant.EPOCH);
    }

    @Test
    void nullServiceReturnsNull() {
        assertThat(CpeMapper.toCpe23(null)).isNull();
    }

    @Test
    void nullNameReturnsNull() {
        assertThat(CpeMapper.toCpe23(svc(null, "1.0"))).isNull();
    }

    @Test
    void emptyNameReturnsNull() {
        // empty string sanitizes to empty slug → null
        assertThat(CpeMapper.toCpe23(svc("", "1.0"))).isNull();
    }

    @Test
    void whitespaceOnlyNameReturnsNull() {
        // whitespace stripped by sanitize → empty slug → null
        assertThat(CpeMapper.toCpe23(svc("   ", "1.0"))).isNull();
    }

    @Test
    void opensshNameProducesCanonicalCpe() {
        String cpe = CpeMapper.toCpe23(svc("OpenSSH", "8.2"));
        assertThat(cpe).isEqualTo("cpe:2.3:a:openssh:openssh:8.2:*:*:*:*:*:*:*");
    }

    @Test
    void nullVersionMapsToWildcard() {
        String cpe = CpeMapper.toCpe23(svc("openssh", null));
        assertThat(cpe).contains(":*:");
        // version field should be the wildcard
        assertThat(cpe).isEqualTo("cpe:2.3:a:openssh:openssh:*:*:*:*:*:*:*:*");
    }

    @Test
    void sanitizationStripsForbiddenChars() {
        // "My Service!" → slug "myservice"
        String cpe = CpeMapper.toCpe23(svc("My Service!", "1.0"));
        assertThat(cpe).isEqualTo("cpe:2.3:a:myservice:myservice:1.0:*:*:*:*:*:*:*");
    }
}

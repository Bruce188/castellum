package io.castellum.discovery.probe;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link Port8080Fingerprinter}.
 */
class Port8080FingerprinterTest {

    private static final ObjectMapper OM = new ObjectMapper();

    private static final String TRAEFIK_OVERVIEW = """
        {"http":{"routers":{"total":2,"warnings":0,"errors":0},"services":{"total":2}}}
        """;

    private static final String CADVISOR_MACHINE = """
        {"num_cores":4,"memory_capacity":8589934592,"machine_id":"abc"}
        """;

    @Test
    void identify_traefikShape_returnsTraefik() {
        TraefikApiClient traefik = new TraefikApiClient(uri -> {
            if (uri.getPath().equals("/api/overview")) return Optional.of(TRAEFIK_OVERVIEW);
            return Optional.empty();
        });
        CAdvisorApiClient cadvisor = new CAdvisorApiClient(uri -> Optional.empty());
        Port8080Fingerprinter fp = new Port8080Fingerprinter(traefik, cadvisor, OM);

        assertThat(fp.identify("10.0.0.1", 8080)).isEqualTo(Port8080Fingerprinter.Identity.TRAEFIK);
    }

    @Test
    void identify_cadvisorShape_returnsCadvisor() {
        TraefikApiClient traefik = new TraefikApiClient(uri -> Optional.empty());
        CAdvisorApiClient cadvisor = new CAdvisorApiClient(uri -> {
            if (uri.getPath().equals("/api/v1.3/machine")) return Optional.of(CADVISOR_MACHINE);
            return Optional.empty();
        });
        Port8080Fingerprinter fp = new Port8080Fingerprinter(traefik, cadvisor, OM);

        assertThat(fp.identify("10.0.0.1", 8080)).isEqualTo(Port8080Fingerprinter.Identity.CADVISOR);
    }

    @Test
    void identify_bothEmpty_returnsUnknown() {
        TraefikApiClient traefik = new TraefikApiClient(uri -> Optional.empty());
        CAdvisorApiClient cadvisor = new CAdvisorApiClient(uri -> Optional.empty());
        Port8080Fingerprinter fp = new Port8080Fingerprinter(traefik, cadvisor, OM);

        assertThat(fp.identify("10.0.0.1", 8080)).isEqualTo(Port8080Fingerprinter.Identity.UNKNOWN);
    }

    @Test
    void identify_traefikResponseButNoCadvisor_returnsTraefik() {
        // Traefik wins when both would answer: Traefik checked first
        TraefikApiClient traefik = new TraefikApiClient(uri -> {
            if (uri.getPath().equals("/api/overview")) return Optional.of(TRAEFIK_OVERVIEW);
            return Optional.empty();
        });
        CAdvisorApiClient cadvisor = new CAdvisorApiClient(uri -> Optional.of(CADVISOR_MACHINE));
        Port8080Fingerprinter fp = new Port8080Fingerprinter(traefik, cadvisor, OM);

        assertThat(fp.identify("10.0.0.1", 8080)).isEqualTo(Port8080Fingerprinter.Identity.TRAEFIK);
    }

    @Test
    void identify_malformedTraefikResponse_fallsThroughToCadvisor() {
        TraefikApiClient traefik = new TraefikApiClient(uri -> Optional.of("{malformed"));
        CAdvisorApiClient cadvisor = new CAdvisorApiClient(uri -> {
            if (uri.getPath().equals("/api/v1.3/machine")) return Optional.of(CADVISOR_MACHINE);
            return Optional.empty();
        });
        Port8080Fingerprinter fp = new Port8080Fingerprinter(traefik, cadvisor, OM);

        assertThat(fp.identify("10.0.0.1", 8080)).isEqualTo(Port8080Fingerprinter.Identity.CADVISOR);
    }
}

package io.castellum.threatintel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import io.castellum.threatintel.stix.StixBundle;
import io.castellum.threatintel.stix.StixIndicator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * MAC-only placeholder devices ({@code ipAddress = "mac:..."}, see
 * {@link io.castellum.discovery.PlaceholderIp}) must be excluded from STIX export exactly
 * like null-IP devices: no infrastructure SDO, no indicator, and the synthetic sentinel
 * string must not leak into any STIX property — {@code "[ipv4-addr:value = 'mac:...']"}
 * would be an invalid pattern shipped to downstream consumers.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BundleAssemblerPlaceholderIpTest {

    @Mock DeviceRepository deviceRepository;
    @Mock NetworkServiceRepository networkServiceRepository;
    @Mock CveRepository cveRepository;
    @Mock EpssScoreRepository epssScoreRepository;
    @Mock KevEntryRepository kevEntryRepository;
    @Mock CveMatcher cveMatcher;

    private static final Clock FIXED_CLOCK =
        Clock.fixed(Instant.parse("2026-04-29T12:00:00Z"), ZoneOffset.UTC);

    private BundleAssembler assembler;

    @BeforeEach
    void setUp() {
        assembler = new BundleAssembler(
            deviceRepository, networkServiceRepository, cveRepository,
            epssScoreRepository, kevEntryRepository, cveMatcher, FIXED_CLOCK);
    }

    /**
     * Control device (real IP) and placeholder device both carry the same qualifying
     * (KEV-listed) CVE via identical services. Only the real-IP device may produce an
     * indicator; the serialized bundle must contain no {@code "mac:"} substring anywhere.
     */
    @Test
    @SuppressWarnings("unchecked")
    void assemble_placeholderIpDeviceWithQualifyingCve_noIndicatorAndNoSentinelInJson() throws Exception {
        Device real = new Device(1L, "10.0.0.5", null, null,
            Instant.EPOCH, Instant.EPOCH, Criticality.HIGH);
        Device placeholder = new Device(2L, "mac:aa-bb-cc-dd-ee-ff", "switch01", "aa:bb:cc:dd:ee:ff",
            Instant.EPOCH, Instant.EPOCH, Criticality.HIGH);
        when(deviceRepository.findAll()).thenReturn(List.of(real, placeholder));
        when(cveRepository.findAllStixViews()).thenReturn(List.of());

        // Identical qualifying service on BOTH devices — even if service rows exist for the
        // placeholder device, no indicator may be emitted for it.
        NetworkService svcReal = service(1L);
        NetworkService svcPlaceholder = service(2L);
        when(networkServiceRepository.findByDeviceIdIn(any()))
            .thenReturn(List.of(svcReal, svcPlaceholder));

        Cve cve = new Cve();
        cve.setCveId("CVE-2026-0001");
        cve.setCvssV31Score(new BigDecimal("9.8"));
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));

        when(epssScoreRepository.findAllByCveIdIn(any())).thenReturn(List.of());
        KevEntry kev = new KevEntry();
        kev.setCveId("CVE-2026-0001");
        when(kevEntryRepository.findAllByCveIdIn(any())).thenReturn(List.of(kev));

        StixBundle bundle = assembler.assemble();

        // Exactly one indicator — for the real-IP device only.
        List<StixIndicator> indicators = bundle.objects().stream()
            .filter(StixIndicator.class::isInstance)
            .map(StixIndicator.class::cast)
            .toList();
        assertThat(indicators)
            .as("placeholder-IP device must not produce an indicator")
            .hasSize(1);
        assertThat(indicators.get(0).name()).isEqualTo("CVE-2026-0001 on 10.0.0.5");
        assertThat(indicators.get(0).pattern()).isEqualTo("[ipv4-addr:value = '10.0.0.5']");

        // Service batch query receives only the real-IP device id.
        ArgumentCaptor<Collection<Long>> idsCaptor = ArgumentCaptor.forClass(Collection.class);
        verify(networkServiceRepository).findByDeviceIdIn(idsCaptor.capture());
        assertThat(idsCaptor.getValue())
            .as("placeholder devices are excluded from the service batch query")
            .containsExactly(1L);

        // The sentinel must not appear in ANY STIX property of the serialized bundle.
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        String json = mapper.writeValueAsString(bundle);
        assertThat(json)
            .as("no placeholder sentinel may leak into the STIX bundle JSON")
            .doesNotContain("mac:");
    }

    private static NetworkService service(long deviceId) {
        NetworkService svc = new NetworkService();
        svc.setDeviceId(deviceId);
        svc.setPort(80);
        svc.setProtocol("tcp");
        svc.setName("testapp");
        svc.setVersion("1.0");
        return svc;
    }
}

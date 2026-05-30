package io.castellum.threatintel;

import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.cve.CveStixView;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.EpssScore;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import io.castellum.threatintel.stix.StixBundle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * NB1 — empty-collection guard tests for {@link BundleAssembler}.
 *
 * <p>Two unguarded sites in the production code:
 * <ol>
 *   <li>{@code networkServiceRepository.findByDeviceIdIn(deviceIds)} — called even when
 *       {@code deviceIds} is empty (empty fleet or no device has an IP address), which
 *       may emit an {@code IN ()} SQL clause on some databases.</li>
 *   <li>{@code epssScoreRepository.findAllByCveIdIn(matchedCveIds)} — called even when
 *       {@code matchedCveIds} is empty (no CPE-matched CVEs across the fleet), causing
 *       the same hazard.</li>
 * </ol>
 *
 * <p>These tests are RED until an {@code isEmpty()} guard is added at each unguarded site.
 * Once guarded, each test verifies: (a) no exception is thrown, (b) the bundle is returned
 * correctly (identity-only for the empty cases), and (c) the guarded repository method is
 * NOT called when the input collection is empty.
 */
@ExtendWith(MockitoExtension.class)
class BundleAssemblerEmptyFleetTest {

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

    // ── NB1-a: empty fleet (no devices) ─────────────────────────────────────

    /**
     * With zero devices in the fleet, {@code deviceIds} is empty.
     * The assembler must NOT call {@code findByDeviceIdIn} with an empty collection
     * (which could generate {@code IN ()} SQL), and must return a valid bundle.
     */
    @Test
    void assemble_emptyFleet_doesNotCallFindByDeviceIdIn() {
        when(deviceRepository.findAll()).thenReturn(List.of());
        when(cveRepository.findAllStixViews()).thenReturn(List.of());

        StixBundle bundle = assembler.assemble();

        assertThat(bundle).isNotNull();
        assertThat(bundle.objects()).as("empty fleet → only identity object in bundle").hasSize(1);

        // RED: currently BundleAssembler calls findByDeviceIdIn even with an empty list.
        // After adding the isEmpty() guard this verify must pass.
        verify(networkServiceRepository, never()).findByDeviceIdIn(any());
    }

    // ── NB1-b: fleet with devices but none have IP addresses ─────────────────

    /**
     * Devices exist but none has an IP address, so the filtered {@code deviceIds} list
     * is empty. Same guard requirement as the zero-device case.
     */
    @Test
    void assemble_devicesWithoutIpAddress_doesNotCallFindByDeviceIdIn() {
        Device noIp = new Device();
        noIp.setIpAddress(null);
        noIp.setFirstSeen(Instant.now());
        noIp.setLastSeen(Instant.now());

        when(deviceRepository.findAll()).thenReturn(List.of(noIp));
        when(cveRepository.findAllStixViews()).thenReturn(List.of());

        StixBundle bundle = assembler.assemble();

        assertThat(bundle).isNotNull();

        // RED: same unguarded findByDeviceIdIn call with an empty filtered list.
        verify(networkServiceRepository, never()).findByDeviceIdIn(any());
    }

    // ── NB1-c: fleet with devices + services but no CPE matches → empty matchedCveIds ─

    /**
     * Devices and services exist but no CPE string can be derived (e.g. service name is null),
     * so {@code matchedCveIds} is empty. The assembler must NOT call
     * {@code epssScoreRepository.findAllByCveIdIn} or {@code kevEntryRepository.findAllByCveIdIn}
     * with an empty collection.
     */
    @Test
    void assemble_noMatchedCves_doesNotCallFindAllByCveIdIn() {
        Device d = new Device();
        d.setIpAddress("10.0.0.1");
        d.setFirstSeen(Instant.now());
        d.setLastSeen(Instant.now());

        when(deviceRepository.findAll()).thenReturn(List.of(d));
        when(cveRepository.findAllStixViews()).thenReturn(List.of());

        // Service whose name is null → CpeMapper.toCpe23 returns null → no CPE match
        NetworkService svc = new NetworkService();
        svc.setDeviceId(1L);
        svc.setPort(80);
        svc.setProtocol("tcp");
        // name is null — no CPE can be derived

        when(networkServiceRepository.findByDeviceIdIn(any())).thenReturn(List.of(svc));

        StixBundle bundle = assembler.assemble();

        assertThat(bundle).isNotNull();

        // RED: currently BundleAssembler calls findAllByCveIdIn on the EPSS and KEV repos
        // even when matchedCveIds is empty.
        verify(epssScoreRepository, never()).findAllByCveIdIn(any());
        verify(kevEntryRepository, never()).findAllByCveIdIn(any());
    }

    // ── NB1-d: no exception thrown (survives without blowing up) ─────────────

    /**
     * Sanity gate — the assembler must not throw any exception when processing an empty fleet.
     * This is the minimum correctness bar before the guard optimisation.
     */
    @Test
    void assemble_emptyFleet_doesNotThrow() {
        when(deviceRepository.findAll()).thenReturn(List.of());
        when(cveRepository.findAllStixViews()).thenReturn(List.of());

        assertThatCode(() -> assembler.assemble())
            .as("assemble() must not throw for an empty fleet")
            .doesNotThrowAnyException();
    }
}

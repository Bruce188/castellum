package io.castellum.threatintel;

import io.castellum.cve.Cve;
import io.castellum.cve.CveCpeMatch;
import io.castellum.cve.CveCpeMatchRepository;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.cve.CveStixView;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssScore;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import io.castellum.threatintel.stix.StixBundle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * NB3 — IN-list chunking test for {@link BundleAssembler}.
 *
 * <p>When the number of matched CVE IDs exceeds a chunk size threshold (e.g. 500),
 * the assembler must split the IDs into batches and union the results from each
 * {@code findAllByCveIdIn} call, rather than issuing a single huge {@code IN (1500)}
 * query that may breach database limits or degrade query-plan quality.
 *
 * <p>This test is RED until a chunking helper is applied to the {@code findAllByCveIdIn}
 * call sites.
 *
 * <p><b>Chunking contract being asserted:</b>
 * <ol>
 *   <li>With 1500 matched CVE IDs, {@code epssScoreRepository.findAllByCveIdIn} must be
 *       called at least 3 times (proving ≤500 per chunk for a 1500-item set).</li>
 *   <li>Each individual invocation receives ≤500 IDs.</li>
 *   <li>The combined set of IDs across all calls equals the full 1500-item input
 *       (no IDs dropped or duplicated).</li>
 * </ol>
 *
 * <p>The matching CVE ID set is simulated by stubbing the matcher and service repos
 * so the assembler believes 1500 distinct CVEs are matched across the fleet's services.
 */
@ExtendWith(MockitoExtension.class)
class BundleAssemblerChunkingTest {

    private static final int LARGE_CVE_COUNT = 1500;
    private static final int MAX_CHUNK_SIZE = 500;

    @Mock DeviceRepository deviceRepository;
    @Mock NetworkServiceRepository networkServiceRepository;
    @Mock CveRepository cveRepository;
    @Mock EpssScoreRepository epssScoreRepository;
    @Mock KevEntryRepository kevEntryRepository;
    @Mock CveMatcher cveMatcher;

    @Captor ArgumentCaptor<Collection<String>> epssChunkCaptor;
    @Captor ArgumentCaptor<Collection<String>> kevChunkCaptor;

    private static final Clock FIXED_CLOCK =
        Clock.fixed(Instant.parse("2026-04-29T12:00:00Z"), ZoneOffset.UTC);

    private BundleAssembler assembler;

    /**
     * Builds a minimal Cve stub usable by BundleAssembler (needs getCveId()).
     */
    private static Cve buildCve(String cveId) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setDescription("chunking test CVE " + cveId);
        cve.setCvssV31Score(BigDecimal.valueOf(9.8));
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        return cve;
    }

    /**
     * Builds a minimal CveStixView mock for the corpus stub (findAllStixViews).
     */
    private static CveStixView buildCveView(String cveId) {
        CveStixView view = mock(CveStixView.class);
        when(view.getCveId()).thenReturn(cveId);
        when(view.getDescription()).thenReturn("chunking test CVE " + cveId);
        return view;
    }

    @BeforeEach
    void setUp() {
        assembler = new BundleAssembler(
            deviceRepository, networkServiceRepository, cveRepository,
            epssScoreRepository, kevEntryRepository, cveMatcher, FIXED_CLOCK);
    }

    /**
     * Verifies chunking behaviour: 1500 matched CVE IDs must be processed in
     * batches of ≤500 (at least 3 calls to {@code findAllByCveIdIn}).
     *
     * <p>This test is EXPECTED TO FAIL (RED) until the chunking helper is applied.
     * Current production code issues a single call with all 1500 IDs.
     */
    @Test
    void assemble_largeCveIdSet_chunksEpssBatchInto500MaxSlices() {
        // Build 1500 CVEs that the fleet's single service will match
        List<Cve> largeCveList = new ArrayList<>(LARGE_CVE_COUNT);
        for (int i = 0; i < LARGE_CVE_COUNT; i++) {
            largeCveList.add(buildCve(String.format("CVE-2025-%05d", i + 1)));
        }

        // One device with an IP address
        Device d = new Device();
        d.setIpAddress("10.0.0.1");
        d.setFirstSeen(Instant.now());
        d.setLastSeen(Instant.now());
        d.setCriticality(Criticality.MEDIUM);
        when(deviceRepository.findAll()).thenReturn(List.of(d));

        // CVE corpus (all 1500) — lightweight projection stubs
        List<CveStixView> largeCveViewList = new ArrayList<>(LARGE_CVE_COUNT);
        for (int i = 0; i < LARGE_CVE_COUNT; i++) {
            largeCveViewList.add(buildCveView(String.format("CVE-2025-%05d", i + 1)));
        }
        when(cveRepository.findAllStixViews()).thenReturn(largeCveViewList);

        // One service whose CPE resolves and matches all 1500 CVEs
        NetworkService svc = new NetworkService();
        svc.setDeviceId(1L);
        svc.setPort(502);
        svc.setProtocol("tcp");
        svc.setName("testapp");
        svc.setVersion("1.0");
        when(networkServiceRepository.findByDeviceIdIn(any())).thenReturn(List.of(svc));
        when(cveMatcher.findVulnerable("cpe:2.3:a:testapp:testapp:1.0:*:*:*:*:*:*:*"))
            .thenReturn(largeCveList);

        // EPSS and KEV return empty lists regardless of the chunk
        when(epssScoreRepository.findAllByCveIdIn(any())).thenReturn(List.of());
        when(kevEntryRepository.findAllByCveIdIn(any())).thenReturn(List.of());

        StixBundle bundle = assembler.assemble();
        assertThat(bundle).isNotNull();

        // ── RED assertion: chunking must split the 1500-id call into ≥3 batches ──
        //
        // Current code: one call with all 1500 ids → this verify fails (only 1 call).
        // After chunking: ≥3 calls (e.g. 500 + 500 + 500 for a 500-chunk strategy).
        verify(epssScoreRepository, atLeast(3)).findAllByCveIdIn(epssChunkCaptor.capture());

        // Each captured batch must be ≤ MAX_CHUNK_SIZE
        for (Collection<String> chunk : epssChunkCaptor.getAllValues()) {
            assertThat(chunk.size())
                .as("each EPSS IN-list batch must be ≤ %d ids", MAX_CHUNK_SIZE)
                .isLessThanOrEqualTo(MAX_CHUNK_SIZE);
        }

        // Union of all chunks must cover the full 1500-id set (no drops, no duplication)
        java.util.Set<String> allSentIds = new java.util.LinkedHashSet<>();
        for (Collection<String> chunk : epssChunkCaptor.getAllValues()) {
            allSentIds.addAll(chunk);
        }
        java.util.Set<String> expectedIds = new java.util.LinkedHashSet<>();
        for (Cve cve : largeCveList) {
            expectedIds.add(cve.getCveId());
        }
        assertThat(allSentIds)
            .as("union of all chunked EPSS batches must equal the full matched CVE id set")
            .containsExactlyInAnyOrderElementsOf(expectedIds);
    }

    /**
     * Same chunking contract for the KEV repository — a separate call site in BundleAssembler.
     */
    @Test
    void assemble_largeCveIdSet_chunksKevBatchInto500MaxSlices() {
        List<Cve> largeCveList = new ArrayList<>(LARGE_CVE_COUNT);
        for (int i = 0; i < LARGE_CVE_COUNT; i++) {
            largeCveList.add(buildCve(String.format("CVE-2025-%05d", i + 1)));
        }

        Device d = new Device();
        d.setIpAddress("10.0.0.1");
        d.setFirstSeen(Instant.now());
        d.setLastSeen(Instant.now());
        d.setCriticality(Criticality.MEDIUM);
        when(deviceRepository.findAll()).thenReturn(List.of(d));

        List<CveStixView> largeCveViewList = new ArrayList<>(LARGE_CVE_COUNT);
        for (int i = 0; i < LARGE_CVE_COUNT; i++) {
            largeCveViewList.add(buildCveView(String.format("CVE-2025-%05d", i + 1)));
        }
        when(cveRepository.findAllStixViews()).thenReturn(largeCveViewList);

        NetworkService svc = new NetworkService();
        svc.setDeviceId(1L);
        svc.setPort(502);
        svc.setProtocol("tcp");
        svc.setName("testapp");
        svc.setVersion("1.0");
        when(networkServiceRepository.findByDeviceIdIn(any())).thenReturn(List.of(svc));
        when(cveMatcher.findVulnerable("cpe:2.3:a:testapp:testapp:1.0:*:*:*:*:*:*:*"))
            .thenReturn(largeCveList);

        when(epssScoreRepository.findAllByCveIdIn(any())).thenReturn(List.of());
        when(kevEntryRepository.findAllByCveIdIn(any())).thenReturn(List.of());

        assembler.assemble();

        // RED: same expectation for KEV repo chunking
        verify(kevEntryRepository, atLeast(3)).findAllByCveIdIn(kevChunkCaptor.capture());

        for (Collection<String> chunk : kevChunkCaptor.getAllValues()) {
            assertThat(chunk.size())
                .as("each KEV IN-list batch must be ≤ %d ids", MAX_CHUNK_SIZE)
                .isLessThanOrEqualTo(MAX_CHUNK_SIZE);
        }

        java.util.Set<String> allSentIds = new java.util.LinkedHashSet<>();
        for (Collection<String> chunk : kevChunkCaptor.getAllValues()) {
            allSentIds.addAll(chunk);
        }
        java.util.Set<String> expectedIds = new java.util.LinkedHashSet<>();
        for (Cve cve : largeCveList) {
            expectedIds.add(cve.getCveId());
        }
        assertThat(allSentIds)
            .as("union of all chunked KEV batches must equal the full matched CVE id set")
            .containsExactlyInAnyOrderElementsOf(expectedIds);
    }
}

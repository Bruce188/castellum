package io.castellum.cve;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditLogRepository;
import io.castellum.audit.AuditService;
import io.castellum.cve.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@DataJpaTest
@Import({NvdSyncService.class, AuditService.class, JacksonAutoConfiguration.class})
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate",
    "castellum.nvd.results-per-page=10"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class NvdSyncServiceTest {

    @Autowired
    NvdSyncService syncService;

    @Autowired
    CveRepository cveRepository;

    @Autowired
    CveCpeMatchRepository cveCpeMatchRepository;

    @Autowired
    AuditLogRepository auditLogRepository;

    @MockBean
    NvdClient nvdClient;

    @Autowired
    ObjectMapper objectMapper;

    private static final Instant SINCE = Instant.parse("2026-04-01T00:00:00Z");
    private static final Instant UNTIL = Instant.parse("2026-04-29T00:00:00Z");

    private NvdCveResponse loadFixture() throws Exception {
        try (var is = getClass().getResourceAsStream("/cve/nvd-page-sample.json")) {
            assertNotNull(is);
            ObjectMapper om = new ObjectMapper();
            return om.readValue(is, NvdCveResponse.class);
        }
    }

    private NvdCveResponse emptyPage() {
        return new NvdCveResponse(0, 0, 0, "NVD_CVE", "2.0", "2026-04-29T00:00:00.000", List.of());
    }

    @Test
    void bulkPull_upsertsCvesFromMockedClient() throws Exception {
        NvdCveResponse fixture = loadFixture();
        // First call returns fixture (startIndex=0), second call returns empty (startIndex=10)
        when(nvdClient.fetchPage(any(), any(), eq(0), anyInt())).thenReturn(fixture);
        when(nvdClient.fetchPage(any(), any(), eq(10), anyInt())).thenReturn(emptyPage());

        syncService.bulkPull(SINCE, UNTIL);

        assertEquals(fixture.vulnerabilities().size(), cveRepository.count());
        assertTrue(cveRepository.findByCveId("CVE-2020-15778").isPresent());
    }

    @Test
    void bulkPull_isIdempotent_reRunningSameWindowDoesNotDuplicate() throws Exception {
        NvdCveResponse fixture = loadFixture();
        when(nvdClient.fetchPage(any(), any(), eq(0), anyInt())).thenReturn(fixture);
        when(nvdClient.fetchPage(any(), any(), eq(10), anyInt())).thenReturn(emptyPage());

        syncService.bulkPull(SINCE, UNTIL);
        long countAfterFirst = cveRepository.count();

        syncService.bulkPull(SINCE, UNTIL);
        long countAfterSecond = cveRepository.count();

        assertEquals(countAfterFirst, countAfterSecond);
        assertTrue(cveRepository.findByCveId("CVE-2020-15778").isPresent());
    }

    @Test
    void bulkPull_revisedCveUpdatesExistingRow() throws Exception {
        // First run: CVE-2020-15778 with score 7.8, versionEndExcluding=8.4
        NvdCveResponse first = buildResponseWithCve("CVE-2020-15778", new BigDecimal("7.8"), "8.4");
        when(nvdClient.fetchPage(any(), any(), eq(0), anyInt())).thenReturn(first);
        when(nvdClient.fetchPage(any(), any(), eq(10), anyInt())).thenReturn(emptyPage());

        syncService.bulkPull(SINCE, UNTIL);

        Cve cveAfterFirst = cveRepository.findByCveId("CVE-2020-15778").orElseThrow();
        assertEquals(new BigDecimal("7.8"), cveAfterFirst.getCvssV31Score());

        // Second run: CVE-2020-15778 with score 8.8, versionEndExcluding=8.5
        NvdCveResponse second = buildResponseWithCve("CVE-2020-15778", new BigDecimal("8.8"), "8.5");
        when(nvdClient.fetchPage(any(), any(), eq(0), anyInt())).thenReturn(second);
        when(nvdClient.fetchPage(any(), any(), eq(10), anyInt())).thenReturn(emptyPage());

        syncService.bulkPull(SINCE, UNTIL);

        Cve cveAfterSecond = cveRepository.findByCveId("CVE-2020-15778").orElseThrow();
        assertEquals(new BigDecimal("8.8"), cveAfterSecond.getCvssV31Score());

        List<CveCpeMatch> matches = cveCpeMatchRepository.findByCveFk(cveAfterSecond.getId());
        assertEquals(1, matches.size());
        assertEquals("8.5", matches.get(0).getVersionEndExcluding());
    }

    @Test
    void bulkPull_writesOneAuditEventPerWindowSlice() throws Exception {
        // 200-day window forces 2 slices (120 + 80 days)
        Instant since200 = Instant.now().minus(Duration.ofDays(200));
        Instant until200 = Instant.now();

        when(nvdClient.fetchPage(any(), any(), anyInt(), anyInt())).thenReturn(emptyPage());

        syncService.bulkPull(since200, until200);

        List<?> auditEvents = auditLogRepository.findByActor("nvd-sync");
        assertEquals(2, auditEvents.size());
        auditEvents.forEach(e -> assertEquals("BULK_PULL",
            ((io.castellum.audit.AuditLog) e).getAction()));
    }

    @Test
    void incrementalPull_onEmptyMirror_defaultsTo120DaysAgo() throws Exception {
        // Ensure the CVE table is empty for this test
        cveCpeMatchRepository.deleteAll();
        cveCpeMatchRepository.flush();
        cveRepository.deleteAll();
        cveRepository.flush();

        when(nvdClient.fetchPage(any(), any(), anyInt(), anyInt())).thenReturn(emptyPage());

        Instant beforeCall = Instant.now();
        ArgumentCaptor<Instant> startCaptor = ArgumentCaptor.forClass(Instant.class);
        syncService.incrementalPull();
        Instant afterCall = Instant.now();

        verify(nvdClient, atLeastOnce()).fetchPage(startCaptor.capture(), any(), anyInt(), anyInt());
        Instant captured = startCaptor.getValue();
        // The cursor should be approximately 120 days before the call time
        Instant expectedMin = beforeCall.minus(Duration.ofDays(120)).minus(Duration.ofSeconds(30));
        Instant expectedMax = afterCall.minus(Duration.ofDays(120)).plus(Duration.ofSeconds(30));
        assertTrue(!captured.isBefore(expectedMin) && !captured.isAfter(expectedMax),
            "Default cursor should be ~120 days ago, got: " + captured
            + " expected between " + expectedMin + " and " + expectedMax);
    }

    @Test
    void incrementalPull_usesMaxLastModifiedAsCursor() throws Exception {
        Instant cursor = Instant.parse("2026-04-01T00:00:00Z");
        Cve existing = new Cve();
        existing.setCveId("CVE-SEED-001");
        existing.setLastModified(cursor);
        existing.setRawJson("{}");
        existing.setFetchedAt(Instant.now());
        cveRepository.save(existing);

        when(nvdClient.fetchPage(any(), any(), anyInt(), anyInt())).thenReturn(emptyPage());

        ArgumentCaptor<Instant> startCaptor = ArgumentCaptor.forClass(Instant.class);
        syncService.incrementalPull();

        verify(nvdClient, atLeastOnce()).fetchPage(startCaptor.capture(), any(), anyInt(), anyInt());
        Instant captured = startCaptor.getValue();
        // Should use MAX(last_modified) which is exactly 2026-04-01T00:00:00Z
        long diffMillis = Math.abs(Duration.between(captured, cursor).toMillis());
        assertTrue(diffMillis < 1000, "Cursor should match the seeded last_modified");
    }

    @Test
    void sliceWindow_splitsRangeIntoMax120DaySlices() {
        Instant since = Instant.parse("2026-01-01T00:00:00Z");
        Instant until = since.plus(Duration.ofDays(250));

        List<NvdSyncService.WindowSlice> slices = NvdSyncService.sliceWindow(since, until);

        assertEquals(3, slices.size(), "250 days should produce 3 slices (120+120+10)");
        for (NvdSyncService.WindowSlice slice : slices) {
            Duration d = Duration.between(slice.start(), slice.end());
            assertTrue(d.toDays() <= 120, "Each slice must be <= 120 days");
        }
        assertEquals(since, slices.get(0).start(), "First slice start must equal 'since'");
        assertEquals(until, slices.get(slices.size() - 1).end(), "Last slice end must equal 'until'");
    }

    private NvdCveResponse buildResponseWithCve(String cveId, BigDecimal score, String versionEndExcluding) {
        NvdCpeMatch cpeMatch = new NvdCpeMatch(
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            true, null, null, null, versionEndExcluding, null);
        NvdNode node = new NvdNode("OR", false, List.of(cpeMatch));
        NvdConfiguration config = new NvdConfiguration("AND", List.of(node));

        NvdCvssV31.NvdCvssV31Data cvssData = new NvdCvssV31.NvdCvssV31Data(score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        NvdCvssV31 cvss31 = new NvdCvssV31(cvssData);
        NvdMetrics metrics = new NvdMetrics(List.of(cvss31), null, null);

        NvdCveItem item = new NvdCveItem(
            cveId,
            "2020-08-04T19:32:00.000",
            "2023-11-07T03:18:00.640",
            "Modified",
            List.of(new NvdDescription("en", "Test CVE description")),
            metrics,
            List.of(config));

        NvdVulnerability vuln = new NvdVulnerability(item);
        return new NvdCveResponse(1, 0, 1, "NVD_CVE", "2.0", "2026-04-29T12:00:00.000", List.of(vuln));
    }
}

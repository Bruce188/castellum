package io.castellum.risk;

import io.castellum.audit.AuditLogRepository;
import io.castellum.audit.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@DataJpaTest
@Import({EpssIngestionService.class, EpssUpsertService.class, AuditService.class, JacksonAutoConfiguration.class})
class EpssIngestionServiceTest {

    @Autowired EpssIngestionService service;
    @Autowired EpssScoreRepository repo;
    @Autowired AuditLogRepository auditLogRepository;
    @MockBean EpssClient client;

    private BufferedReader cannedReader() {
        return new BufferedReader(new InputStreamReader(
            getClass().getResourceAsStream("/epss/epss-sample.csv"), StandardCharsets.UTF_8));
    }

    @BeforeEach
    void setUp() throws Exception {
        when(client.fetchGunzippedReader()).thenAnswer(inv -> cannedReader());
    }

    @Test
    void ingest_upsertsRowsFromMockedClient() throws Exception {
        service.ingest();
        assertThat(repo.count()).isEqualTo(5);
        var openssh = repo.findByCveId("CVE-2020-15778").orElseThrow();
        assertThat(openssh.getEpss().doubleValue()).isCloseTo(0.5, org.assertj.core.data.Offset.offset(1e-6));
    }

    @Test
    void ingest_isIdempotent() throws Exception {
        service.ingest();
        service.ingest();
        assertThat(repo.count()).isEqualTo(5);
    }

    @Test
    void ingest_writesOneAuditEventPerRun() throws Exception {
        service.ingest();
        var events = auditLogRepository.findAll().stream()
            .filter(a -> "risk-feeds".equals(a.getActor()) && "EPSS_INGEST".equals(a.getAction()))
            .toList();
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getResourceType()).isEqualTo("epss");
    }

    @Test
    void ingest_revisedRowUpdatesExistingRow() throws Exception {
        service.ingest();  // first pass with sample (epss=0.5 for CVE-2020-15778)
        String revised = """
                #model_version:v1,score_date:2026-04-30T00:00:00Z
                cve,epss,percentile
                CVE-2020-15778,0.99000,0.99900
                """;
        when(client.fetchGunzippedReader()).thenReturn(new BufferedReader(new java.io.StringReader(revised)));
        service.ingest();
        var openssh = repo.findByCveId("CVE-2020-15778").orElseThrow();
        assertThat(openssh.getEpss().doubleValue()).isCloseTo(0.99, org.assertj.core.data.Offset.offset(1e-6));
    }
}

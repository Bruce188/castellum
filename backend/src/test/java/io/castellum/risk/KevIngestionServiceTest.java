package io.castellum.risk;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditLogRepository;
import io.castellum.audit.AuditService;
import io.castellum.risk.dto.KevFeedDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@DataJpaTest
@Import({KevIngestionService.class, KevUpsertService.class, AuditService.class, JacksonAutoConfiguration.class})
class KevIngestionServiceTest {

    @Autowired KevIngestionService service;
    @Autowired KevEntryRepository repo;
    @Autowired AuditLogRepository auditLogRepository;
    @MockBean KevClient client;

    private KevFeedDto fixture;

    @BeforeEach
    void setUp() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        try (var stream = getClass().getResourceAsStream("/kev/kev-sample.json")) {
            fixture = mapper.readValue(stream, KevFeedDto.class);
        }
        when(client.fetch()).thenReturn(fixture);
    }

    @Test
    void ingest_upsertsAllEntriesFromMockedFeed() throws Exception {
        service.ingest();
        assertThat(repo.count()).isEqualTo(fixture.count());
        assertThat(repo.existsByCveId("CVE-2020-15778")).isTrue();
    }

    @Test
    void ingest_isIdempotent() throws Exception {
        service.ingest();
        service.ingest();
        assertThat(repo.count()).isEqualTo(fixture.count());
    }

    @Test
    void ingest_revisedEntryUpdatesExistingRow() throws Exception {
        service.ingest();
        ObjectMapper mapper = new ObjectMapper();
        String revisedJson = """
            {"title":"CISA","catalogVersion":"2026.04.30","dateReleased":"2026-04-30T00:00:00.000Z","count":1,
             "vulnerabilities":[{"cveID":"CVE-2020-15778","vendorProject":"OpenBSD-Updated","product":"OpenSSH",
                                  "vulnerabilityName":"OpenSSH scp Command Injection","dateAdded":"2022-02-15",
                                  "shortDescription":"updated","requiredAction":"updated","dueDate":"2022-08-15",
                                  "knownRansomwareCampaignUse":"Unknown","notes":"","cwes":["CWE-78"]}]}
            """;
        KevFeedDto revised = mapper.readValue(revisedJson, KevFeedDto.class);
        when(client.fetch()).thenReturn(revised);
        service.ingest();
        var entry = repo.findByCveId("CVE-2020-15778").orElseThrow();
        assertThat(entry.getVendorProject()).isEqualTo("OpenBSD-Updated");
    }

    @Test
    void ingest_writesOneAuditEventPerRun() throws Exception {
        service.ingest();
        var events = auditLogRepository.findAll().stream()
            .filter(a -> "risk-feeds".equals(a.getActor()) && "KEV_INGEST".equals(a.getAction()))
            .toList();
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getResourceId()).isEqualTo(fixture.catalogVersion());
    }

    @Test
    void ingest_handlesMissingOptionalFields() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String partial = """
            {"title":"x","catalogVersion":"v","dateReleased":"2026-04-29T00:00:00.000Z","count":1,
             "vulnerabilities":[{"cveID":"CVE-9999-0001","vendorProject":"x","product":"y",
                                  "vulnerabilityName":"z","dateAdded":"2026-01-01",
                                  "shortDescription":"","requiredAction":"","dueDate":null,
                                  "knownRansomwareCampaignUse":"Unknown","notes":"","cwes":null}]}
            """;
        when(client.fetch()).thenReturn(mapper.readValue(partial, KevFeedDto.class));
        service.ingest();
        assertThat(repo.existsByCveId("CVE-9999-0001")).isTrue();
    }
}

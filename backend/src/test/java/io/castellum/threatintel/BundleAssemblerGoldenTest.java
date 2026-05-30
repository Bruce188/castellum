package io.castellum.threatintel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.cve.Cve;
import io.castellum.cve.CveCpeMatch;
import io.castellum.cve.CveCpeMatchRepository;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.*;
import io.castellum.threatintel.stix.StixBundle;
import io.castellum.threatintel.stix.StixSchemaValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import io.castellum.threatintel.stix.StixObject;
import io.castellum.threatintel.stix.StixVulnerability;

import java.math.BigDecimal;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

/**
 * Golden-file test for BundleAssembler. Seeds 3 devices + 4 CVEs and validates:
 * 1. The assembled bundle matches the golden fixture (structural equality).
 * 2. The bundle validates against the bundled OASIS STIX 2.1 schemas (AC#1).
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class BundleAssemblerGoldenTest {

    @Autowired private DeviceRepository deviceRepository;
    @Autowired private NetworkServiceRepository networkServiceRepository;
    @Autowired private CveRepository cveRepository;
    @Autowired private CveCpeMatchRepository cveCpeMatchRepository;
    @Autowired private EpssScoreRepository epssScoreRepository;
    @Autowired private KevEntryRepository kevEntryRepository;
    @Autowired private CveMatcher cveMatcher;
    @Autowired @Qualifier("stixObjectMapper") ObjectMapper stixObjectMapper;

    private BundleAssembler assembler;

    private static final Clock FIXED_CLOCK =
        Clock.fixed(Instant.parse("2026-04-29T12:00:00Z"), ZoneOffset.UTC);

    @BeforeEach
    void seed() {
        // Device 1: HIGH criticality, has hostname
        Device d1 = new Device();
        d1.setIpAddress("10.0.0.5");
        d1.setHostname("plc-01");
        d1.setFirstSeen(Instant.now());
        d1.setLastSeen(Instant.now());
        d1.setCriticality(Criticality.HIGH);
        d1 = deviceRepository.save(d1);

        // Device 2: MEDIUM criticality, has hostname
        Device d2 = new Device();
        d2.setIpAddress("10.0.0.6");
        d2.setHostname("plc-02");
        d2.setFirstSeen(Instant.now());
        d2.setLastSeen(Instant.now());
        d2.setCriticality(Criticality.MEDIUM);
        d2 = deviceRepository.save(d2);

        // Device 3: LOW criticality, null hostname (name = ip)
        Device d3 = new Device();
        d3.setIpAddress("10.0.0.7");
        d3.setFirstSeen(Instant.now());
        d3.setLastSeen(Instant.now());
        d3.setCriticality(Criticality.LOW);
        d3 = deviceRepository.save(d3);

        // CVE 1: CVSS 9.8 -> composite >= 7.0 -> indicator
        Cve cve1 = new Cve();
        cve1.setCveId("CVE-2026-0001");
        cve1.setDescription("High severity RCE in testapp");
        cve1.setCvssV31Score(new BigDecimal("9.8"));
        cve1.setLastModified(Instant.now());
        cve1.setRawJson("{}");
        cve1.setFetchedAt(Instant.now());
        cve1 = cveRepository.save(cve1);

        // CVE 2: KEV -> indicator regardless of score
        Cve cve2 = new Cve();
        cve2.setCveId("CVE-2026-0002");
        cve2.setDescription("KEV exploit in testapp");
        cve2.setCvssV31Score(new BigDecimal("5.0"));
        cve2.setLastModified(Instant.now());
        cve2.setRawJson("{}");
        cve2.setFetchedAt(Instant.now());
        cve2 = cveRepository.save(cve2);
        KevEntry kev2 = new KevEntry();
        kev2.setCveId("CVE-2026-0002");
        kev2.setDateAdded(LocalDate.now());
        kev2.setVendorProject("testvendor");
        kev2.setProduct("testapp");
        kev2.setIngestedAt(Instant.now());
        kevEntryRepository.save(kev2);

        // CVE 3: CVSS 4.0, no KEV -> composite < 7.0 -> NO indicator
        Cve cve3 = new Cve();
        cve3.setCveId("CVE-2026-0003");
        cve3.setDescription("Low severity in testapp");
        cve3.setCvssV31Score(new BigDecimal("4.0"));
        cve3.setLastModified(Instant.now());
        cve3.setRawJson("{}");
        cve3.setFetchedAt(Instant.now());
        cve3 = cveRepository.save(cve3);

        // CVE 4: no CPE match -> NOT in bundle
        Cve cve4 = new Cve();
        cve4.setCveId("CVE-2026-0004");
        cve4.setDescription("Unmatched CVE");
        cve4.setCvssV31Score(new BigDecimal("7.5"));
        cve4.setLastModified(Instant.now());
        cve4.setRawJson("{}");
        cve4.setFetchedAt(Instant.now());
        cveRepository.save(cve4);

        // Service on device 1 for testapp 1.0 -> matches CVE 1,2,3
        NetworkService svc1 = new NetworkService();
        svc1.setDeviceId(d1.getId());
        svc1.setPort(502);
        svc1.setProtocol("tcp");
        svc1.setName("testapp");
        svc1.setVersion("1.0");
        svc1.setObservedAt(Instant.now());
        networkServiceRepository.save(svc1);

        // CPE matches for CVE 1,2,3 -> testapp
        CveCpeMatch m1 = new CveCpeMatch();
        m1.setCveFk(cve1.getId());
        m1.setCpe23Uri("cpe:2.3:a:testapp:testapp:*:*:*:*:*:*:*:*");
        m1.setVulnerable(true);
        cveCpeMatchRepository.save(m1);

        CveCpeMatch m2 = new CveCpeMatch();
        m2.setCveFk(cve2.getId());
        m2.setCpe23Uri("cpe:2.3:a:testapp:testapp:*:*:*:*:*:*:*:*");
        m2.setVulnerable(true);
        cveCpeMatchRepository.save(m2);

        CveCpeMatch m3 = new CveCpeMatch();
        m3.setCveFk(cve3.getId());
        m3.setCpe23Uri("cpe:2.3:a:testapp:testapp:*:*:*:*:*:*:*:*");
        m3.setVulnerable(true);
        cveCpeMatchRepository.save(m3);

        assembler = new BundleAssembler(
            deviceRepository, networkServiceRepository, cveRepository,
            epssScoreRepository, kevEntryRepository, cveMatcher, FIXED_CLOCK);
    }

    @Test
    void assembledBundle_idKeyedObjectSet_hasStablePerTypeCounts() {
        StixBundle bundle = assembler.assemble();

        Map<String, StixObject> byId = new LinkedHashMap<>();
        for (StixObject o : bundle.objects()) {
            byId.put(o.id(), o);
        }
        assertThat(byId).as("id-keyed object set size").hasSize(15);

        Map<String, Long> byType = bundle.objects().stream()
            .collect(Collectors.groupingBy(
                o -> o.getClass().getSimpleName(), Collectors.counting()));
        assertThat(byType).containsOnly(
            entry("StixIdentity", 1L),
            entry("StixInfrastructure", 3L),
            entry("StixVulnerability", 4L),
            entry("StixRelationship", 5L),
            entry("StixIndicator", 2L));

        assertThat(byId.values().stream()
            .filter(o -> o instanceof StixVulnerability)
            .map(o -> ((StixVulnerability) o).name()))
            .contains("CVE-2026-0004");
    }

    @Test
    void assembledBundle_matchesGoldenFixture_andValidatesAgainstOasisSchema() throws Exception {
        StixBundle bundle = assembler.assemble();
        String json = stixObjectMapper.writeValueAsString(bundle);

        // Normalize: replace random bundle ID with placeholder
        String normalized = json.replaceAll(
            "\"id\"\\s*:\\s*\"bundle--[0-9a-fA-F-]+\"",
            "\"id\":\"bundle--PLACEHOLDER\"");

        // Check schema validation (AC#1)
        List<String> errors = StixSchemaValidator.validate(json);
        assertThat(errors).as("STIX schema validation errors").isEmpty();

        // NB5: fail-on-missing — a missing golden fixture is a test failure, not a bootstrap trigger.
        // To regenerate the fixture after an intentional format change, delete the file and run
        // the assembler manually (e.g. via a one-off @Test annotated with @Disabled) to produce
        // a fresh golden, then commit it. Self-bootstrap is removed so accidental deletion is caught.
        URL goldenUrl = getClass().getClassLoader().getResource("golden/stix-bundle-v1.json");
        assertThat(goldenUrl)
            .as("Golden fixture 'src/test/resources/golden/stix-bundle-v1.json' is missing. "
                + "Restore it from git or regenerate intentionally — self-bootstrap removed (NB5).")
            .isNotNull();

        String expected = Files.readString(Path.of(goldenUrl.toURI()));
        // Compare structurally: parse both and re-serialize for stable comparison
        Object expParsed = stixObjectMapper.readValue(expected, Object.class);
        Object actParsed = stixObjectMapper.readValue(normalized, Object.class);
        assertThat(stixObjectMapper.writeValueAsString(actParsed))
            .as("Bundle JSON should match golden fixture")
            .isEqualTo(stixObjectMapper.writeValueAsString(expParsed));
    }

    @Test
    void assembledBundle_hasExplicitStixBundleShape() throws Exception {
        StixBundle bundle = assembler.assemble();
        String json = stixObjectMapper.writeValueAsString(bundle);
        JsonNode root = stixObjectMapper.readTree(json);

        // AC1: top-level bundle shape
        assertThat(root.path("type").asText())
            .as("bundle type must be 'bundle'")
            .isEqualTo("bundle");
        assertThat(root.path("id").asText())
            .as("bundle id must be non-blank")
            .isNotBlank();
        assertThat(root.path("id").asText())
            .as("bundle id must start with 'bundle--'")
            .startsWith("bundle--");
        assertThat(root.path("spec_version").asText())
            .as("bundle spec_version must be '2.1'")
            .isEqualTo("2.1");

        // objects array must exist and be non-empty
        assertThat(root.path("objects").isArray())
            .as("'objects' must be a JSON array")
            .isTrue();
        assertThat(root.path("objects"))
            .as("'objects' array must be non-empty")
            .isNotEmpty();

        // every object must carry a non-blank type and id
        for (JsonNode obj : root.path("objects")) {
            assertThat(obj.path("type").asText())
                .as("each STIX object must have a non-blank 'type'")
                .isNotBlank();
            assertThat(obj.path("id").asText())
                .as("each STIX object must have a non-blank 'id'")
                .isNotBlank();
            if (obj.has("spec_version")) {
                assertThat(obj.path("spec_version").asText())
                    .as("when 'spec_version' is present it must be non-blank")
                    .isNotBlank();
            }
        }
    }
}

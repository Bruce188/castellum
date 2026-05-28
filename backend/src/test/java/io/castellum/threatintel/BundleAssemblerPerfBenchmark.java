package io.castellum.threatintel;

import io.castellum.cve.Cve;
import io.castellum.cve.CveCpeMatch;
import io.castellum.cve.CveCpeMatchRepository;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
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
import jakarta.persistence.EntityManagerFactory;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.LongSummaryStatistics;

@SpringBootTest
@Disabled("perf — run manually; not a CI gate")
@Tag("perf")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class BundleAssemblerPerfBenchmark {

    @Autowired private DeviceRepository deviceRepository;
    @Autowired private NetworkServiceRepository networkServiceRepository;
    @Autowired private CveRepository cveRepository;
    @Autowired private CveCpeMatchRepository cveCpeMatchRepository;
    @Autowired private EpssScoreRepository epssScoreRepository;
    @Autowired private KevEntryRepository kevEntryRepository;
    @Autowired private CveMatcher cveMatcher;
    @Autowired private EntityManagerFactory emf;

    private BundleAssembler assembler;

    private static final Clock FIXED_CLOCK =
        Clock.fixed(Instant.parse("2026-04-29T12:00:00Z"), ZoneOffset.UTC);

    // Seed constants
    private static final int DEVICE_COUNT = 30;
    // 4 service "product families", each device gets one svc; each family mapped to a CPE slug
    private static final String[] SVC_NAMES = {"modbus", "profinet", "dnp3", "iec61850"};
    // Total CVEs = CVES_PER_FAMILY * 4 families
    private static final int CVES_PER_FAMILY = 50; // 200 CVEs total
    // Subset that get KEV entries (every 5th CVE in each family)
    private static final int KEV_STRIDE = 5;
    // Subset that get EPSS entries (every 3rd CVE in each family)
    private static final int EPSS_STRIDE = 3;

    @BeforeEach
    void seed() {
        // Build 30 devices
        List<Device> devices = new ArrayList<>();
        for (int i = 0; i < DEVICE_COUNT; i++) {
            Device d = new Device();
            d.setIpAddress("10.1." + (i / 256) + "." + (i % 256));
            d.setHostname("ot-device-" + i);
            d.setFirstSeen(Instant.now());
            d.setLastSeen(Instant.now());
            d.setCriticality(Criticality.values()[i % Criticality.values().length]);
            d = deviceRepository.save(d);
            devices.add(d);
        }

        // Build CVEs and CPE matches per product family
        for (int f = 0; f < SVC_NAMES.length; f++) {
            String family = SVC_NAMES[f];
            // CPE slug as CpeMapper would derive from the name (lowercase, alphanumeric only)
            String slug = family.toLowerCase().replaceAll("[^a-z0-9_-]", "");
            String cpePfx = "cpe:2.3:a:" + slug + ":" + slug + ":";

            for (int c = 0; c < CVES_PER_FAMILY; c++) {
                int seq = f * CVES_PER_FAMILY + c + 1;
                Cve cve = new Cve();
                cve.setCveId("CVE-2025-" + String.format("%05d", seq));
                cve.setDescription("Perf benchmark CVE " + seq + " for " + family);
                // Alternate CVSS so some go above indicator threshold, some below
                cve.setCvssV31Score(new BigDecimal(c % 3 == 0 ? "9.8" : "4.5"));
                cve.setLastModified(Instant.now());
                cve.setRawJson("{}");
                cve.setFetchedAt(Instant.now());
                cve = cveRepository.save(cve);

                // CPE match wired to the family slug (wildcard version)
                CveCpeMatch match = new CveCpeMatch();
                match.setCveFk(cve.getId());
                match.setCpe23Uri(cpePfx + "*:*:*:*:*:*:*:*");
                match.setVulnerable(true);
                cveCpeMatchRepository.save(match);

                // EPSS for every EPSS_STRIDE-th CVE in this family
                if (c % EPSS_STRIDE == 0) {
                    EpssScore epss = new EpssScore();
                    epss.setCveId(cve.getCveId());
                    epss.setEpss(new BigDecimal("0.42"));
                    epss.setPercentile(new BigDecimal("0.85"));
                    epss.setScoreDate(LocalDate.now());
                    epss.setIngestedAt(Instant.now());
                    epssScoreRepository.save(epss);
                }

                // KEV for every KEV_STRIDE-th CVE in this family
                if (c % KEV_STRIDE == 0) {
                    KevEntry kev = new KevEntry();
                    kev.setCveId(cve.getCveId());
                    kev.setDateAdded(LocalDate.now());
                    kev.setVendorProject("vendor-" + family);
                    kev.setProduct(family);
                    kev.setIngestedAt(Instant.now());
                    kevEntryRepository.save(kev);
                }
            }
        }

        // Assign one NetworkService per device, cycling through the four product families
        for (int i = 0; i < devices.size(); i++) {
            Device d = devices.get(i);
            String name = SVC_NAMES[i % SVC_NAMES.length];
            NetworkService svc = new NetworkService();
            svc.setDeviceId(d.getId());
            svc.setPort(502 + i);
            svc.setProtocol("tcp");
            svc.setName(name);
            svc.setVersion("1.0");
            svc.setObservedAt(Instant.now());
            networkServiceRepository.save(svc);
        }

        assembler = new BundleAssembler(
            deviceRepository, networkServiceRepository, cveRepository,
            epssScoreRepository, kevEntryRepository, cveMatcher, FIXED_CLOCK);
    }

    @Test
    void benchmark_sqlStatementCount() {
        Statistics stats = emf.unwrap(SessionFactory.class).getStatistics();
        stats.setStatisticsEnabled(true);

        // Warm-up iterations (wall-clock not captured here)
        for (int i = 0; i < 2; i++) {
            assembler.assemble();
        }

        // Measured runs for wall-clock median
        int runs = 5;
        long[] wallMs = new long[runs];
        long sqlCount = 0;

        for (int r = 0; r < runs; r++) {
            stats.clear();
            long before = stats.getPrepareStatementCount();
            long t0 = System.nanoTime();
            StixBundle bundle = assembler.assemble();
            long ms = (System.nanoTime() - t0) / 1_000_000;
            sqlCount = stats.getPrepareStatementCount() - before;
            wallMs[r] = ms;
            // Prevent DCE
            if (bundle == null) throw new IllegalStateException("null bundle");
        }

        // Compute median
        java.util.Arrays.sort(wallMs);
        long medianMs = wallMs[runs / 2];

        int cveCorpus = SVC_NAMES.length * CVES_PER_FAMILY;
        int fleetSize = DEVICE_COUNT;
        int svcsPerDevice = 1;

        System.out.println("[PERF] assemble() SQL statements = " + sqlCount
            + " ; wall-clock ms = " + medianMs
            + " ; corpus=" + cveCorpus + " CVEs"
            + " ; fleet=" + fleetSize + " devices x " + svcsPerDevice + " svc");
    }
}

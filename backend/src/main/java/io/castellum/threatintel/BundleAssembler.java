package io.castellum.threatintel;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.graph.CpeMapper;
import io.castellum.risk.*;
import io.castellum.threatintel.stix.*;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.*;

/**
 * Assembles a STIX 2.1 bundle from the current Castellum risk state.
 *
 * <p>Indicator threshold: {@code kev = true OR composite >= 7.0}.
 * TODO Q1 follow-up: make configurable via castellum.threat-intel.indicator-threshold.
 */
@Service
public class BundleAssembler {

    private static final double INDICATOR_COMPOSITE_THRESHOLD = 7.0;
    // TODO Q1 follow-up: make configurable via castellum.threat-intel.indicator-threshold

    private final DeviceRepository deviceRepository;
    private final NetworkServiceRepository networkServiceRepository;
    private final CveRepository cveRepository;
    private final EpssScoreRepository epssScoreRepository;
    private final KevEntryRepository kevEntryRepository;
    private final CveMatcher cveMatcher;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public BundleAssembler(DeviceRepository deviceRepository,
                           NetworkServiceRepository networkServiceRepository,
                           CveRepository cveRepository,
                           EpssScoreRepository epssScoreRepository,
                           KevEntryRepository kevEntryRepository,
                           CveMatcher cveMatcher) {
        this(deviceRepository, networkServiceRepository, cveRepository,
             epssScoreRepository, kevEntryRepository, cveMatcher, Clock.systemUTC());
    }

    public BundleAssembler(DeviceRepository deviceRepository,
                           NetworkServiceRepository networkServiceRepository,
                           CveRepository cveRepository,
                           EpssScoreRepository epssScoreRepository,
                           KevEntryRepository kevEntryRepository,
                           CveMatcher cveMatcher,
                           Clock clock) {
        this.deviceRepository = deviceRepository;
        this.networkServiceRepository = networkServiceRepository;
        this.cveRepository = cveRepository;
        this.epssScoreRepository = epssScoreRepository;
        this.kevEntryRepository = kevEntryRepository;
        this.cveMatcher = cveMatcher;
        this.clock = clock;
    }

    public StixBundle assemble() {
        OffsetDateTime now = OffsetDateTime.now(clock);

        // Identity SDO — one per bundle, all other SDOs reference it
        StixIdentity identity = StixIdentity.castellum(StixIds.IDENTITY_ID, now);

        // Use a map to dedupe by ID (deterministic seeds, last-wins)
        Map<String, StixObject> objects = new LinkedHashMap<>();
        objects.put(identity.id(), identity);

        List<Device> devices = deviceRepository.findAll();
        for (Device device : devices) {
            if (device.getIpAddress() == null) continue;

            String deviceName = device.getHostname() != null ? device.getHostname() : device.getIpAddress();
            Map<String, Object> castellumExt = new LinkedHashMap<>();
            castellumExt.put("ip_address", device.getIpAddress());
            if (device.getMacAddress() != null) {
                castellumExt.put("mac_address", device.getMacAddress());
            }
            if (device.getCriticality() != null) {
                castellumExt.put("criticality", device.getCriticality().name());
            }
            Map<String, Map<String, Object>> extensions = Map.of("x_castellum", castellumExt);

            StixInfrastructure infra = new StixInfrastructure(
                "infrastructure", "2.1",
                StixIds.forDevice(device.getIpAddress()),
                now, now,
                StixIds.IDENTITY_ID,
                deviceName,
                List.of("unknown"),
                extensions
            );
            objects.put(infra.id(), infra);
        }

        // Vulnerability SDOs for all CVEs, then relationships
        List<Cve> allCves = cveRepository.findAll();
        for (Cve cve : allCves) {
            StixVulnerability vuln = new StixVulnerability(
                "vulnerability", "2.1",
                StixIds.forCve(cve.getCveId()),
                now, now,
                StixIds.IDENTITY_ID,
                cve.getCveId(),
                cve.getDescription(),
                List.of(new ExternalReference("cve", cve.getCveId()))
            );
            objects.put(vuln.id(), vuln);
        }

        // Per-device, per-service: match CVEs, emit affects relationships and indicators
        for (Device device : devices) {
            if (device.getIpAddress() == null) continue;
            String infraId = StixIds.forDevice(device.getIpAddress());

            List<NetworkService> services = networkServiceRepository.findByDeviceId(device.getId());
            for (NetworkService svc : services) {
                String cpe = CpeMapper.toCpe23(svc);
                if (cpe == null) continue;

                List<Cve> matchedCves = cveMatcher.findVulnerable(cpe);
                for (Cve cve : matchedCves) {
                    String vulnId = StixIds.forCve(cve.getCveId());

                    // Always: affects relationship
                    StixRelationship affects = new StixRelationship(
                        "relationship", "2.1",
                        StixIds.forRelationship("affects", vulnId, infraId),
                        now, now,
                        StixIds.IDENTITY_ID,
                        "affects", vulnId, infraId
                    );
                    objects.put(affects.id(), affects);

                    // Compute composite score
                    double cvssN = CvssExtractor.normalized(cve);
                    double epss = epssScoreRepository.findByCveId(cve.getCveId())
                        .map(e -> e.getEpss().doubleValue()).orElse(0.0);
                    boolean kev = kevEntryRepository.existsByCveId(cve.getCveId());
                    Criticality criticality = device.getCriticality() != null ? device.getCriticality() : Criticality.MEDIUM;
                    RiskScore riskScore = CompositeScorer.score(new RiskInputs(cvssN, epss, kev, criticality));
                    BigDecimal composite = riskScore.score();

                    // Indicator threshold: kev OR composite >= 7.0
                    if (kev || composite.doubleValue() >= INDICATOR_COMPOSITE_THRESHOLD) {
                        String indicatorId = StixIds.forIndicator(cve.getCveId(), device.getIpAddress());
                        StixIndicator indicator = new StixIndicator(
                            "indicator", "2.1",
                            indicatorId,
                            now, now,
                            StixIds.IDENTITY_ID,
                            cve.getCveId() + " on " + device.getIpAddress(),
                            List.of("malicious-activity"),
                            "[ipv4-addr:value = '" + device.getIpAddress() + "']",
                            "stix",
                            now,
                            composite
                        );
                        objects.put(indicator.id(), indicator);

                        // targets relationship: indicator -> infrastructure
                        StixRelationship targets = new StixRelationship(
                            "relationship", "2.1",
                            StixIds.forRelationship("targets", indicatorId, infraId),
                            now, now,
                            StixIds.IDENTITY_ID,
                            "targets", indicatorId, infraId
                        );
                        objects.put(targets.id(), targets);
                    }
                }
            }
        }

        return StixBundle.of(StixIds.forBundle(), new ArrayList<>(objects.values()));
    }
}

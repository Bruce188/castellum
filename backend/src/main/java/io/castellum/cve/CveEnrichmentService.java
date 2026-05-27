package io.castellum.cve;

import io.castellum.risk.CompositeScorer;
import io.castellum.risk.Criticality;
import io.castellum.risk.CvssExtractor;
import io.castellum.risk.EpssScore;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import io.castellum.risk.RiskInputs;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Batch + per-row enricher that decorates {@link Cve} rows with the three v3-F1
 * fields exposed on the wire: CISA KEV listing membership ({@code kev}), raw EPSS
 * probability ({@code epss}), and composite risk score ({@code composite}).
 *
 * <p><b>Batch path ({@link #enrich(Collection, Criticality)}):</b> two repo calls
 * (one for KEV, one for EPSS) regardless of input size; per-row {@link CompositeScorer}
 * computation. Used by the list endpoints to keep N+1 chatter at zero.
 *
 * <p><b>Detail path ({@link #enrichOne(Cve, Criticality)}):</b> per-row
 * {@code existsByCveId} + {@code findByCveId}; single-row fast path.
 *
 * <p>Composite is {@code null} when no CVSS metric is populated (per
 * {@link CvssExtractor#normalized(Cve)} returning 0.0 — distinguishes "no signal"
 * from a true 0.00 score). Epss is {@code null} when no {@code epss_score} row exists;
 * the composite formula treats missing EPSS as 0.0 (the value that contributes no
 * additional weight). Kev is always {@code Boolean.TRUE} or {@code Boolean.FALSE} —
 * never null.
 */
@Service
public class CveEnrichmentService {

    private final KevEntryRepository kevRepo;
    private final EpssScoreRepository epssRepo;

    public CveEnrichmentService(KevEntryRepository kevRepo, EpssScoreRepository epssRepo) {
        this.kevRepo = kevRepo;
        this.epssRepo = epssRepo;
    }

    public Map<String, Enrichment> enrich(Collection<Cve> cves, Criticality criticality) {
        if (cves.isEmpty()) return Map.of();
        Set<String> cveIds = cves.stream().map(Cve::getCveId).collect(Collectors.toSet());
        Set<String> kevIds = kevRepo.findAllByCveIdIn(cveIds).stream()
                .map(KevEntry::getCveId)
                .collect(Collectors.toSet());
        Map<String, BigDecimal> epssMap = epssRepo.findAllByCveIdIn(cveIds).stream()
                .collect(Collectors.toMap(EpssScore::getCveId, EpssScore::getEpss));
        Map<String, Enrichment> out = new HashMap<>();
        for (Cve cve : cves) {
            boolean kev = kevIds.contains(cve.getCveId());
            BigDecimal epss = epssMap.get(cve.getCveId());
            BigDecimal composite = computeComposite(cve, kev, epss, criticality);
            out.put(cve.getCveId(), new Enrichment(Boolean.valueOf(kev), epss, composite));
        }
        return out;
    }

    public Enrichment enrichOne(Cve cve, Criticality criticality) {
        boolean kev = kevRepo.existsByCveId(cve.getCveId());
        BigDecimal epss = epssRepo.findByCveId(cve.getCveId())
                .map(EpssScore::getEpss)
                .orElse(null);
        BigDecimal composite = computeComposite(cve, kev, epss, criticality);
        return new Enrichment(Boolean.valueOf(kev), epss, composite);
    }

    private BigDecimal computeComposite(Cve cve, boolean kev, BigDecimal epss, Criticality criticality) {
        double cvssNorm = CvssExtractor.normalized(cve);
        if (cvssNorm == 0.0) return null;
        double epssVal = epss != null ? Math.min(1.0, Math.max(0.0, epss.doubleValue())) : 0.0;
        return CompositeScorer.score(new RiskInputs(cvssNorm, epssVal, kev, criticality)).score();
    }

    /**
     * Result tuple carrying the three v3-F1 wire fields. {@code kev} is never null;
     * {@code epss} is null when no EPSS row exists; {@code composite} is null when no
     * CVSS metric is populated for the underlying CVE.
     */
    public record Enrichment(Boolean kev, BigDecimal epss, BigDecimal composite) {}
}

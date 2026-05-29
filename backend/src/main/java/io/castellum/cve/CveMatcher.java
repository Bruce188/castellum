package io.castellum.cve;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Scan-time CPE→CVE matcher that reads the local NVD mirror only.
 * Supports range-aware matching: versionStartIncluding/Excluding and versionEndIncluding/Excluding.
 */
@Service
public class CveMatcher {

    private final CveRepository cveRepository;
    private final CveCpeMatchRepository cveCpeMatchRepository;

    public CveMatcher(CveRepository cveRepository, CveCpeMatchRepository cveCpeMatchRepository) {
        this.cveRepository = cveRepository;
        this.cveCpeMatchRepository = cveCpeMatchRepository;
    }

    /**
     * Evidence tuple returned by {@link #findVulnerableWithEvidence}: pairs each matched
     * CVE with the {@link CveCpeMatch} row that caused the match, giving the caller the
     * matched CPE URI (product+version) and the version-range bounds without re-querying.
     *
     * @param cve         the matched CVE entity.
     * @param matchedRow  the first {@code cve_cpe_match} row whose bounds included the
     *                    queried version. {@code cpe23Uri} and the version bounds are the
     *                    evidence for AC1 display (matched product+version, range).
     */
    public record MatchEvidence(Cve cve, CveCpeMatch matchedRow) {}

    /**
     * Like {@link #findVulnerable(String)} but also returns the matching
     * {@link CveCpeMatch} row for each CVE, enabling callers to surface the matched
     * CPE URI (product+version) and the version-range bounds.
     *
     * <p>Semantics are identical to {@link #findVulnerable(String)} — this method is
     * ADDITIVE and does NOT change {@code findVulnerable}'s behaviour. Both iterate the
     * same candidate set and apply the same {@link #matches} predicate.
     *
     * @param cpe23 the queried CPE 2.3 URI (e.g. {@code cpe:2.3:a:postgresql:postgresql:16.0:...})
     * @return list of {@link MatchEvidence}, one per matched CVE, sorted by cveId ASC.
     */
    public List<MatchEvidence> findVulnerableWithEvidence(String cpe23) {
        Cpe23 query = Cpe23.parse(cpe23);
        String prefix = query.prefixVendorProduct();
        List<CveCpeMatch> candidates = cveCpeMatchRepository.findByCpe23UriStartingWithOrderByIdAsc(prefix);

        // Map cveFk → first matching CveCpeMatch row (first-wins, lowest-id row selected —
        // the CVE-FK dedup semantics match findVulnerable's Set; the id ordering is unique to
        // this evidence path and ensures a stable, deterministic row is returned across calls)
        Map<Long, CveCpeMatch> matchedRows = new LinkedHashMap<>();
        for (CveCpeMatch row : candidates) {
            if (!Boolean.TRUE.equals(row.getVulnerable())) continue;
            if (matchedRows.containsKey(row.getCveFk())) continue; // first-wins
            Cpe23 candidate = safeParse(row.getCpe23Uri());
            if (candidate == null) continue;
            if (!matches(query, candidate, row)) continue;
            matchedRows.put(row.getCveFk(), row);
        }

        if (matchedRows.isEmpty()) return List.of();
        List<MatchEvidence> result = new ArrayList<>();
        cveRepository.findAllById(matchedRows.keySet()).forEach(cve ->
            result.add(new MatchEvidence(cve, matchedRows.get(cve.getId()))));
        result.sort((a, b) -> a.cve().getCveId().compareTo(b.cve().getCveId()));
        return result;
    }

    public List<Cve> findVulnerable(String cpe23) {
        Cpe23 query = Cpe23.parse(cpe23);
        String prefix = query.prefixVendorProduct();
        List<CveCpeMatch> candidates = cveCpeMatchRepository.findByCpe23UriStartingWithOrderByIdAsc(prefix);

        Set<Long> matchedCveFks = new LinkedHashSet<>();
        for (CveCpeMatch row : candidates) {
            if (!Boolean.TRUE.equals(row.getVulnerable())) continue;
            Cpe23 candidate = safeParse(row.getCpe23Uri());
            if (candidate == null) continue;
            if (!matches(query, candidate, row)) continue;
            matchedCveFks.add(row.getCveFk());
        }

        if (matchedCveFks.isEmpty()) return List.of();
        List<Cve> matched = new ArrayList<>();
        cveRepository.findAllById(matchedCveFks).forEach(matched::add);
        matched.sort((a, b) -> a.getCveId().compareTo(b.getCveId()));
        return matched;
    }

    private static boolean matches(Cpe23 query, Cpe23 candidate, CveCpeMatch row) {
        // Vendor + product equality already guaranteed by the prefix lookup.
        // Now apply version semantics.
        String candidateVersion = candidate.version();
        if (!"*".equals(candidateVersion) && !"-".equals(candidateVersion)) {
            // Literal version match required.
            return candidateVersion.equals(query.version());
        }
        // Range row: apply bounds.
        String qv = query.version();
        if (qv == null || qv.isEmpty() || "*".equals(qv) || "-".equals(qv)) {
            // Caller queried with no version — treat as match against any range.
            return true;
        }
        if (row.getVersionStartIncluding() != null && Versions.compare(qv, row.getVersionStartIncluding()) < 0) return false;
        if (row.getVersionStartExcluding() != null && Versions.compare(qv, row.getVersionStartExcluding()) <= 0) return false;
        if (row.getVersionEndIncluding() != null && Versions.compare(qv, row.getVersionEndIncluding()) > 0) return false;
        if (row.getVersionEndExcluding() != null && Versions.compare(qv, row.getVersionEndExcluding()) >= 0) return false;
        return true;
    }

    private static Cpe23 safeParse(String uri) {
        try {
            return Cpe23.parse(uri);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Numeric-aware version comparator. Splits on '.' and compares numerically when both sides
     * are integers, lexicographically otherwise. Known limitations: does NOT match the NVD reference
     * implementation for letter-suffixed versions (e.g. "1.0a" vs "1.0b"). Acceptable for products
     * using MAJOR.MINOR.PATCH versioning (OpenSSH, most server software).
     */
    static final class Versions {
        static int compare(String a, String b) {
            String[] ap = a.split("\\.");
            String[] bp = b.split("\\.");
            int len = Math.max(ap.length, bp.length);
            for (int i = 0; i < len; i++) {
                String ai = i < ap.length ? ap[i] : "0";
                String bi = i < bp.length ? bp[i] : "0";
                Integer aInt = tryInt(ai);
                Integer bInt = tryInt(bi);
                int c;
                if (aInt != null && bInt != null) c = Integer.compare(aInt, bInt);
                else c = ai.compareTo(bi);
                if (c != 0) return c;
            }
            return 0;
        }

        private static Integer tryInt(String s) {
            try {
                return Integer.parseInt(s);
            } catch (NumberFormatException e) {
                return null;
            }
        }
    }
}

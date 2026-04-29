package io.castellum.cve;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
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

    public List<Cve> findVulnerable(String cpe23) {
        Cpe23 query = Cpe23.parse(cpe23);
        String prefix = query.prefixVendorProduct();
        List<CveCpeMatch> candidates = cveCpeMatchRepository.findByCpe23UriStartingWith(prefix);

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

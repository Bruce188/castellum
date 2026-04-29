package io.castellum.risk;

import io.castellum.cve.Cve;

import java.math.BigDecimal;

/**
 * Pure utility: extract a normalized [0, 1] CVSS score from a {@link Cve} row by selecting the
 * maximum non-negative score across v3.1, v3.0, and v2 metrics, then dividing by 10.0.
 *
 * <p>Returns 0.0 when no CVSS metric is populated (or all populated values are negative).
 *
 * <p>Shared by {@link io.castellum.web.RiskController} and the attack-graph builder.
 */
public final class CvssExtractor {

    private CvssExtractor() {
        throw new UnsupportedOperationException("static utility");
    }

    public static double normalized(Cve cve) {
        BigDecimal best = null;
        if (cve.getCvssV31Score() != null && cve.getCvssV31Score().signum() >= 0) {
            best = cve.getCvssV31Score();
        }
        if (cve.getCvssV30Score() != null && cve.getCvssV30Score().signum() >= 0
                && (best == null || cve.getCvssV30Score().compareTo(best) > 0)) {
            best = cve.getCvssV30Score();
        }
        if (cve.getCvssV2Score() != null && cve.getCvssV2Score().signum() >= 0
                && (best == null || cve.getCvssV2Score().compareTo(best) > 0)) {
            best = cve.getCvssV2Score();
        }
        return best == null ? 0.0 : best.doubleValue() / 10.0;
    }
}

package io.castellum.risk;

import java.math.BigDecimal;
import java.math.RoundingMode;

/**
 * Pure-function composite risk scorer. Static utility; zero state beyond constants.
 *
 * <p>Formula: {@code score = CVSS_on_ten * (1 + EPSS_WEIGHT*EPSS) * (KEV?KEV_MULT:1) * (1 + critFactor) / (1 + CRIT_CRITICAL)}.
 * Result is clamped to [0, 10] and rounded to 2 decimal places (HALF_UP).
 *
 * <p>Constants are hard-coded private static final to enforce golden-test determinism.
 * Tuning the formula requires a Java edit + recompile + golden-test rerun — that is
 * the correct friction point for changes that ripple into auditable scoring.
 *
 * <p>Edge cases (documented honestly):
 * <ul>
 *   <li>All zero/false/LOW → 0.00.</li>
 *   <li>Max CVSS only (1.0, 0, false, LOW) → 5.00. Mid-range — defender-friendly: severity alone is not a fire alarm.</li>
 *   <li>Max CVSS + CRITICAL asset (1.0, 0, false, CRITICAL) → 10.00.</li>
 *   <li>CVSS 0 + EPSS 0.9 + KEV true + HIGH (0, 0.9, true, HIGH) → 0.00. CVSS-zero produces zero — intentional honest behavior.
 *       A KEV-only floor is a follow-up if user feedback warrants; v1 ships without it.</li>
 *   <li>Above-clamp combinations (very high CVSS + high EPSS + KEV + CRITICAL) clamp at 10.00.</li>
 * </ul>
 */
public final class CompositeScorer {

    private static final double EPSS_WEIGHT = 1.0;
    private static final double KEV_MULTIPLIER = 1.5;

    private static final double CRIT_LOW = 0.0;
    private static final double CRIT_MEDIUM = 0.25;
    private static final double CRIT_HIGH = 0.5;
    private static final double CRIT_CRITICAL = 1.0;

    private static final BigDecimal MAX_SCORE = new BigDecimal("10.00");
    private static final BigDecimal MIN_SCORE = BigDecimal.ZERO.setScale(2);

    private CompositeScorer() {
        throw new UnsupportedOperationException("static utility");
    }

    public static RiskScore score(RiskInputs inputs) {
        double cvssOnTen = inputs.cvssNormalized() * 10.0;
        double epssMult = 1.0 + EPSS_WEIGHT * inputs.epss();
        double kevMult = inputs.kev() ? KEV_MULTIPLIER : 1.0;
        double critF = critFactor(inputs.criticality());
        double critMult = 1.0 + critF;

        // Divide by (1 + CRIT_CRITICAL) so the headline scale stays meaningful:
        // max-CVSS + CRITICAL (no other signals) → 10 * 1 * 1 * 2 / 2 = 10.00
        double raw = cvssOnTen * epssMult * kevMult * critMult / (1.0 + CRIT_CRITICAL);

        BigDecimal headline = BigDecimal.valueOf(raw)
            .setScale(2, RoundingMode.HALF_UP);
        if (headline.compareTo(MAX_SCORE) > 0) headline = MAX_SCORE;
        if (headline.compareTo(MIN_SCORE) < 0) headline = MIN_SCORE;

        BigDecimal cvssC = BigDecimal.valueOf(cvssOnTen).setScale(2, RoundingMode.HALF_UP);
        BigDecimal epssC = BigDecimal.valueOf(EPSS_WEIGHT * inputs.epss()).setScale(2, RoundingMode.HALF_UP);
        BigDecimal kevC = BigDecimal.valueOf(kevMult - 1.0).setScale(2, RoundingMode.HALF_UP);
        BigDecimal critC = BigDecimal.valueOf(critF).setScale(2, RoundingMode.HALF_UP);

        return new RiskScore(headline, cvssC, epssC, kevC, critC);
    }

    private static double critFactor(Criticality c) {
        return switch (c) {
            case LOW -> CRIT_LOW;
            case MEDIUM -> CRIT_MEDIUM;
            case HIGH -> CRIT_HIGH;
            case CRITICAL -> CRIT_CRITICAL;
        };
    }
}

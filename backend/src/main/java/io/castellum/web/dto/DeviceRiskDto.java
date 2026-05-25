package io.castellum.web.dto;

import java.math.BigDecimal;
import java.util.List;

/**
 * Read-only DTO for {@code GET /api/risk/devices/{id}}. Reports the composite
 * risk score for one device and the CVE IDs that contributed most.
 *
 * <p>Mirrors the documentation style of peer DTOs ({@link DiscoverySourceDto},
 * {@link DiscoverySweepDto}). The codebase has no springdoc-openapi or
 * {@code io.swagger.v3.oas.annotations.media.Schema} on the classpath; record
 * Javadoc is the project's convention for OpenAPI-style field documentation.
 *
 * @param deviceId   primary-key identifier of the device the score applies to.
 * @param score      composite risk score in the range [0.00, 10.00], rounded
 *                   to two decimal places. Combines CVSS, EPSS, KEV membership,
 *                   and device criticality.
 * @param topCveIds  CVE IDs whose composite contribution dominates the score,
 *                   ordered most-contribution-first. Empty if no CVE evidence
 *                   is associated with the device's services.
 * @param components breakdown of the headline {@code score} into its CVSS / EPSS /
 *                   KEV / criticality input components. Surfaces the maxima seen
 *                   across the device's CVE set so the UI can render a "why this
 *                   score?" panel. Nullable when {@code topCveIds} is empty (no
 *                   matched CVEs implies no inputs to break down).
 */
public record DeviceRiskDto(long deviceId, BigDecimal score, List<String> topCveIds, ScoreComponents components) {

    /** Backwards-compatible constructor — older callers that don't supply components. */
    public DeviceRiskDto(long deviceId, BigDecimal score, List<String> topCveIds) {
        this(deviceId, score, topCveIds, null);
    }

    /**
     * Component breakdown of the composite score.
     *
     * @param cvssMax            highest CVSS base score (on the 0-10 scale) observed across the
     *                           device's matched CVEs; 0.00 when no CVEs matched.
     * @param epssMax            highest EPSS exploit-probability score in [0.00, 1.00] across
     *                           the device's matched CVEs; 0.00 when no EPSS data is available.
     * @param kevPresent         true if any matched CVE appears in CISA's Known Exploited
     *                           Vulnerabilities catalog.
     * @param criticalityWeight  numeric weight applied for the device's criticality tier
     *                           (LOW=0.0, MEDIUM=0.25, HIGH=0.5, CRITICAL=1.0).
     */
    public record ScoreComponents(
            BigDecimal cvssMax,
            BigDecimal epssMax,
            boolean kevPresent,
            BigDecimal criticalityWeight) {}
}

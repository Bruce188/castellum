package io.castellum.web.dto;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Read-only DTO for {@code GET /api/cve} (list endpoint). Mirrors the CVE entity
 * without the surrogate {@code id} and without {@code rawJson}, preventing bandwidth
 * waste and avoiding exposure of potentially multi-KB upstream NVD payloads on bulk
 * list responses.
 *
 * <p>The codebase has no springdoc-openapi or {@code io.swagger.v3.oas.annotations}
 * on the classpath; record Javadoc is the project's convention for field documentation.
 *
 * <p><b>v3-F1 enrichment fields (kev, epssScore, compositeScore):</b>
 * <ul>
 *   <li>{@code kev} is never null — defaults to {@code Boolean.FALSE} when no
 *       {@code kev_entry} row exists.</li>
 *   <li>{@code epssScore} is the raw EPSS probability in [0, 1] (NOT percentile); the
 *       frontend renders it as percent via {@code Number(x) * 100}.</li>
 *   <li>{@code compositeScore} is clamped to [0.00, 10.00] with HALF_UP 2-decimal
 *       rounding. In fleet-mode (no {@code deviceId} filter), the composite is
 *       computed against {@code Criticality.MEDIUM} (project default); when a
 *       {@code deviceId} is supplied, the device's actual criticality is used.</li>
 *   <li>{@code BigDecimal} fields serialise to JSON <i>numbers</i> with Spring Boot's
 *       default Jackson configuration (no {@code WRITE_NUMBERS_AS_STRINGS} or
 *       {@code WRITE_BIGDECIMAL_AS_PLAIN} override). The frontend types-side
 *       declares them as {@code string | null} purely as a defensive contract;
 *       its {@code Number(x)} coercion is a no-op on the number-typed wire value.
 *       {@code @WebMvcTest} assertions therefore use numeric {@code jsonPath(...).value(0.5)},
 *       not string {@code .value("0.5")}.</li>
 * </ul>
 *
 * @param cveId         NVD CVE identifier (e.g. {@code CVE-2020-15778}).
 * @param published     timestamp when NVD first published this entry; may be {@code null}.
 * @param lastModified  timestamp of the most recent NVD modification; never {@code null}.
 * @param vulnStatus    NVD vulnerability status string (e.g. {@code Analyzed}); nullable.
 * @param description   English description from NVD; nullable.
 * @param cvssV31Score  CVSS v3.1 base score in the range [0.0, 10.0]; {@code null} if absent.
 * @param cvssV31Vector CVSS v3.1 vector string; {@code null} if absent.
 * @param cvssV30Score  CVSS v3.0 base score; {@code null} if absent.
 * @param cvssV30Vector CVSS v3.0 vector string; {@code null} if absent.
 * @param cvssV2Score   CVSS v2.0 base score; {@code null} if absent.
 * @param cvssV2Vector  CVSS v2.0 vector string; {@code null} if absent.
 * @param fetchedAt     timestamp when Castellum last fetched this record from NVD; nullable.
 * @param kev           CISA KEV listing membership; never {@code null} (defaults to {@code FALSE}).
 * @param epssScore     raw EPSS probability in [0, 1]; {@code null} if no {@code epss_score} row exists.
 * @param compositeScore composite risk score in [0.00, 10.00]; {@code null} if no CVSS metric is populated.
 */
public record CveSummaryDto(
        String cveId,
        Instant published,
        Instant lastModified,
        String vulnStatus,
        String description,
        BigDecimal cvssV31Score,
        String cvssV31Vector,
        BigDecimal cvssV30Score,
        String cvssV30Vector,
        BigDecimal cvssV2Score,
        String cvssV2Vector,
        Instant fetchedAt,
        Boolean kev,
        BigDecimal epssScore,
        BigDecimal compositeScore) {}

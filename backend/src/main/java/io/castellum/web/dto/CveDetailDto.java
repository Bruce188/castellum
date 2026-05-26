package io.castellum.web.dto;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Read-only DTO for {@code GET /api/cve/{cveId}} (detail endpoint). Mirrors the CVE
 * entity without the surrogate {@code id}, and intentionally retains {@code rawJson}
 * so callers with sufficient privilege can access the full upstream NVD payload.
 *
 * <p>Sibling of {@link CveSummaryDto}: the only difference is the presence of
 * {@code rawJson} at the end of the original 12-field tuple. The codebase has no
 * springdoc-openapi or {@code io.swagger.v3.oas.annotations} on the classpath; record
 * Javadoc is the project's convention for field documentation.
 *
 * <p><b>v3-F1 enrichment fields (kev, epssScore, compositeScore):</b> appended AFTER
 * {@code rawJson}. {@code kev} is never null; {@code epssScore} is the raw probability
 * in [0, 1]; {@code compositeScore} is clamped to [0.00, 10.00]. For the detail
 * endpoint, composite uses {@code Criticality.MEDIUM} (no device context). See
 * {@link CveSummaryDto} for the full fleet-mode semantics.
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
 * @param rawJson       the full upstream NVD JSON payload (potentially multi-KB); intentionally
 *                      only exposed on the detail endpoint to avoid bandwidth waste on list calls.
 * @param kev           CISA KEV listing membership; never {@code null} (defaults to {@code FALSE}).
 * @param epssScore     raw EPSS probability in [0, 1]; {@code null} if no {@code epss_score} row exists.
 * @param compositeScore composite risk score in [0.00, 10.00]; {@code null} if no CVSS metric is populated.
 */
public record CveDetailDto(
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
        String rawJson,
        Boolean kev,
        BigDecimal epssScore,
        BigDecimal compositeScore) {}

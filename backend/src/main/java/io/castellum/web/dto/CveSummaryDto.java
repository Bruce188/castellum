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
        Instant fetchedAt) {}

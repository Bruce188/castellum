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
 * @param deviceId  primary-key identifier of the device the score applies to.
 * @param score     composite risk score in the range [0.00, 10.00], rounded
 *                  to two decimal places. Combines CVSS, EPSS, KEV membership,
 *                  and device criticality.
 * @param topCveIds CVE IDs whose composite contribution dominates the score,
 *                  ordered most-contribution-first. Empty if no CVE evidence
 *                  is associated with the device's services.
 */
public record DeviceRiskDto(long deviceId, BigDecimal score, List<String> topCveIds) {}

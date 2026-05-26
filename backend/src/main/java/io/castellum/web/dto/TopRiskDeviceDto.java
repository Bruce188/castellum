package io.castellum.web.dto;

import io.castellum.risk.Criticality;

import java.math.BigDecimal;

/**
 * Read-only DTO for {@code GET /api/risk/top}. Each entry pairs a device's
 * identifying metadata with its composite risk score and the count of
 * KEV-flagged CVEs contributing to that device's risk surface.
 *
 * <p>Distinct from {@link DeviceRiskDto}: this DTO is fleet-ranking optimised —
 * it does NOT carry the per-device {@code topCveIds} list (the dashboard's
 * top-N table does not surface CVE IDs per row; users click through to the
 * detail panel for that). It DOES carry hostname + criticality so the
 * dashboard renders without an additional /api/devices/{id} round-trip per row.
 *
 * @param deviceId    primary-key identifier of the device.
 * @param hostname    device hostname; nullable (devices observed only by IP have no hostname).
 * @param ipAddress   device IPv4/IPv6 address (always present).
 * @param criticality device criticality classification (LOW / MEDIUM / HIGH / CRITICAL).
 * @param score       composite risk score in [0.00, 10.00], rounded to two decimals.
 * @param kevCount    number of distinct KEV-flagged CVEs matched against this device's services.
 */
public record TopRiskDeviceDto(
        long deviceId,
        String hostname,
        String ipAddress,
        Criticality criticality,
        BigDecimal score,
        int kevCount) {}

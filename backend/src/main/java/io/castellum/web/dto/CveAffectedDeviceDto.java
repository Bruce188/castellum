package io.castellum.web.dto;

/**
 * Read-only DTO for {@code GET /api/cve/{cveId}/devices}.
 * Represents a fleet device whose services match the target CVE.
 *
 * @param deviceId       surrogate device PK.
 * @param hostname       device hostname; null if not assigned.
 * @param ipAddress      primary IP address of the device.
 * @param matchedPort    TCP/UDP port of the first matching service.
 * @param matchedService service name (from the matching NetworkService).
 * @param matchedVersion service version string; null/blank if not detected.
 */
public record CveAffectedDeviceDto(
        Long deviceId,
        String hostname,
        String ipAddress,
        int matchedPort,
        String matchedService,
        String matchedVersion) {}

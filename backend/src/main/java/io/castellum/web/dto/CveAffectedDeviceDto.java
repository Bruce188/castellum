package io.castellum.web.dto;

/**
 * Read-only DTO for {@code GET /api/cve/{cveId}/devices}.
 * Represents a fleet device whose services match the target CVE.
 *
 * @param deviceId          surrogate device PK.
 * @param hostname          device hostname; null if not assigned.
 * @param ipAddress         primary IP address of the device.
 * @param matchedPort       TCP/UDP port of the first matching service.
 * @param matchedService    service name (from the matching NetworkService).
 * @param matchedVersion    service version string; null/blank if not detected.
 * @param matchedCpe        CPE 2.3 URI of the NVD row that caused the match
 *                          (e.g. {@code cpe:2.3:a:postgresql:postgresql:*:...});
 *                          null when the caller did not include evidence (legacy path).
 *                          Surfaces the matched product and version for AC1 legibility.
 * @param matchedRangeStart lower version bound of the matching CPE row as a
 *                          human-readable string (e.g. {@code "16.0 (incl.)"}); null
 *                          when the match was on a literal CPE or no lower bound exists.
 * @param matchedRangeEnd   upper version bound of the matching CPE row as a
 *                          human-readable string (e.g. {@code "16.14 (excl.)"}); null
 *                          when the match was on a literal CPE or no upper bound exists.
 */
public record CveAffectedDeviceDto(
        Long deviceId,
        String hostname,
        String ipAddress,
        int matchedPort,
        String matchedService,
        String matchedVersion,
        String matchedCpe,
        String matchedRangeStart,
        String matchedRangeEnd) {

    /**
     * Legacy compact constructor — used by existing callers that do not supply evidence.
     * The three additive evidence fields default to null.
     */
    public CveAffectedDeviceDto(Long deviceId, String hostname, String ipAddress,
                                int matchedPort, String matchedService, String matchedVersion) {
        this(deviceId, hostname, ipAddress, matchedPort, matchedService, matchedVersion,
             null, null, null);
    }
}

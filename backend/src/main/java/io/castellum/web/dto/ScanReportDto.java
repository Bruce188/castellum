package io.castellum.web.dto;

import io.castellum.domain.ScanStatus;
import java.time.Instant;
import java.util.List;

/**
 * Compile stub — Task 2.1 RED phase. Implementer replaces stub body with real logic.
 *
 * Top-level scan report: metadata + summary counts + attributed device snapshot.
 */
public record ScanReportDto(ScanSummary summary, List<SnapshotDeviceDto> devices) {

    /**
     * Scan-level metadata and aggregate counts derived from the attributed snapshot.
     */
    public record ScanSummary(
        Long scanId,
        String cidr,
        String scanType,
        ScanStatus status,
        Instant requestedAt,
        Instant completedAt,
        Long durationMillis,
        String failureReason,
        Integer retryCount,
        int deviceCount,
        int serviceCount,
        int cveCount
    ) {}

    /**
     * Per-device snapshot row in the report.
     *
     * <p>{@code delta} is one of {@code "new"}, {@code "changed"}, or {@code "unchanged"}.
     * "changed" = re-observed/updated by THIS scan, NOT a stored field diff.
     */
    public record SnapshotDeviceDto(
        Long id,
        String ipAddress,
        String hostname,
        String delta,
        List<ServiceRowDto> services,
        List<String> cveIds
    ) {}

    /**
     * Per-service row nested inside a {@link SnapshotDeviceDto}.
     */
    public record ServiceRowDto(
        Long id,
        int port,
        String protocol,
        String name,
        String version
    ) {}
}

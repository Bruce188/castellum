package io.castellum.scan;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.graph.CpeMapper;
import io.castellum.web.dto.ScanReportDto;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Builds a {@link ScanReportDto} for a given scan: metadata, summary counts, and the
 * attributed device snapshot with per-device delta classification and CVE derivation.
 */
@Service
public class ScanReportService {

    private final ScanRepository scanRepository;
    private final DeviceRepository deviceRepository;
    private final NetworkServiceRepository networkServiceRepository;
    private final CveMatcher cveMatcher;

    public ScanReportService(ScanRepository scanRepository,
                             DeviceRepository deviceRepository,
                             NetworkServiceRepository networkServiceRepository,
                             CveMatcher cveMatcher) {
        this.scanRepository = scanRepository;
        this.deviceRepository = deviceRepository;
        this.networkServiceRepository = networkServiceRepository;
        this.cveMatcher = cveMatcher;
    }

    /**
     * Build the report for the given scan.
     *
     * @param scanId the scan to report on
     * @return populated {@link ScanReportDto}
     * @throws NoSuchElementException if {@code scanId} is not found
     */
    public ScanReportDto buildReport(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new NoSuchElementException("Scan not found: " + scanId));

        // Attribution: all devices whose lastSeenByScanId == scanId
        List<Device> devices = deviceRepository.findByLastSeenByScanId(scanId);

        // Batch-fetch all services for the attributed device set
        List<Long> deviceIds = devices.stream().map(Device::getId).toList();
        List<NetworkService> allServices = deviceIds.isEmpty()
                ? List.of()
                : networkServiceRepository.findByDeviceIdIn(deviceIds);

        // Group services by deviceId for per-device processing
        Map<Long, List<NetworkService>> servicesByDevice = allServices.stream()
                .collect(Collectors.groupingBy(NetworkService::getDeviceId));

        // Build per-device snapshot DTOs
        Set<String> allCveIds = new HashSet<>();
        List<ScanReportDto.SnapshotDeviceDto> deviceDtos = new ArrayList<>();

        for (Device device : devices) {
            List<NetworkService> deviceServices = servicesByDevice.getOrDefault(device.getId(), List.of());

            // Compute delta flag
            String delta = computeDelta(device, deviceServices, scan);

            // Derive services and CVEs for this device
            List<ScanReportDto.ServiceRowDto> serviceDtos = new ArrayList<>();
            Set<String> deviceCveIds = new HashSet<>();

            for (NetworkService svc : deviceServices) {
                serviceDtos.add(new ScanReportDto.ServiceRowDto(
                        svc.getId(), svc.getPort(), svc.getProtocol(),
                        svc.getName(), svc.getVersion()));

                String cpe = CpeMapper.toCpe23(svc);
                if (cpe != null) {
                    for (Cve cve : cveMatcher.findVulnerable(cpe)) {
                        deviceCveIds.add(cve.getCveId());
                    }
                }
            }

            allCveIds.addAll(deviceCveIds);
            deviceDtos.add(new ScanReportDto.SnapshotDeviceDto(
                    device.getId(), device.getIpAddress(), device.getHostname(),
                    delta, serviceDtos, new ArrayList<>(deviceCveIds)));
        }

        // Build summary
        long durationMillis = (scan.getCompletedAt() != null && scan.getRequestedAt() != null)
                ? scan.getCompletedAt().toEpochMilli() - scan.getRequestedAt().toEpochMilli()
                : 0L;

        ScanReportDto.ScanSummary summary = new ScanReportDto.ScanSummary(
                scan.getId(),
                scan.getCidr(),
                scan.getScanType(),
                scan.getStatus(),
                scan.getRequestedAt(),
                scan.getCompletedAt(),
                durationMillis,
                scan.getFailureReason(),
                scan.getRetryCount(),
                devices.size(),
                allServices.size(),
                allCveIds.size()
        );

        return new ScanReportDto(summary, deviceDtos);
    }

    /**
     * Compute the delta classification for a device in this scan snapshot.
     *
     * <ul>
     *   <li>"new" — discoveredByScanId == scanId (first discovered by this scan)</li>
     *   <li>"changed" — pre-existing device with at least one service whose observedAt
     *       falls within [scan.requestedAt, scan.completedAt]</li>
     *   <li>"unchanged" — pre-existing device, no service observed in the scan window</li>
     * </ul>
     */
    private String computeDelta(Device device, List<NetworkService> deviceServices, Scan scan) {
        if (scan.getId().equals(device.getDiscoveredByScanId())) {
            return "new";
        }
        // Pre-existing device: check if any service was observed in [requestedAt, completedAt]
        boolean hasServiceInWindow = deviceServices.stream()
                .anyMatch(svc -> svc.getObservedAt() != null
                        && !svc.getObservedAt().isBefore(scan.getRequestedAt())
                        && !svc.getObservedAt().isAfter(scan.getCompletedAt()));
        return hasServiceInWindow ? "changed" : "unchanged";
    }
}

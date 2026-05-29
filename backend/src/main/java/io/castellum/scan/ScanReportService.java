package io.castellum.scan;

import io.castellum.cve.CveMatcher;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.ScanRepository;
import io.castellum.web.dto.ScanReportDto;
import org.springframework.stereotype.Service;

/**
 * Compile stub — Task 2.1 RED phase. Implementer replaces method body with real logic.
 *
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
     * @throws java.util.NoSuchElementException if {@code scanId} is not found
     */
    public ScanReportDto buildReport(Long scanId) {
        // Stub — returns null so tests that assert non-null results fail red.
        return null;
    }
}

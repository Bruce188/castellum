package io.castellum.web;

import io.castellum.scan.ScanType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Scan-submission payload. {@code skipHostDiscovery} is nullable — absent in the
 * JSON leaves it {@code null}, which the controller treats as {@code false}. When
 * {@code true}, SERVICE_DETECT scans the whole CIDR with {@code -Pn} instead of
 * consulting the alive-host inventory; other scan types ignore the flag.
 */
public record ScanRequest(@NotBlank String cidr, @NotNull ScanType type, Boolean skipHostDiscovery) {}

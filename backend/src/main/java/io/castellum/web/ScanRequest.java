package io.castellum.web;

import io.castellum.scan.ScanType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record ScanRequest(@NotBlank String cidr, @NotNull ScanType type) {}

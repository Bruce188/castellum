package io.castellum.risk;

import java.time.Duration;
import java.time.LocalDate;

public record EpssIngestSummary(int rows, int errors, LocalDate scoreDate, Duration duration) {}

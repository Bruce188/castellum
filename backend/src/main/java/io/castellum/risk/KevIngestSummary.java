package io.castellum.risk;

import java.time.Duration;

public record KevIngestSummary(int entries, int errors, String catalogVersion, Duration duration) {}

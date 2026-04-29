package io.castellum.web.dto;

import java.time.Instant;
import java.time.LocalDate;

public record FeedsStatusDto(EpssStatus epss, KevStatus kev) {
    public record EpssStatus(LocalDate scoreDate, long rowCount) {}
    public record KevStatus(Instant lastIngestedAt, long entryCount) {}
}

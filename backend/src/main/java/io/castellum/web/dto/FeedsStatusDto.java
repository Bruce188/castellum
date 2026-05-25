package io.castellum.web.dto;

import java.time.Instant;
import java.time.LocalDate;

public record FeedsStatusDto(EpssStatus epss, KevStatus kev, NvdStatus nvd) {
    public record EpssStatus(LocalDate scoreDate, long rowCount) {}
    public record KevStatus(Instant lastIngestedAt, long entryCount) {}
    public record NvdStatus(Instant lastModified, long rowCount) {}
}

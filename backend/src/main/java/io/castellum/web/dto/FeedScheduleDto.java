package io.castellum.web.dto;

import io.castellum.risk.FeedSyncSchedule;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record FeedScheduleDto(
        boolean enabled,
        String cron,
        Instant lastRunAt,
        String lastStatus,
        String lastError,
        Instant nextRunAt,
        int consecutiveFailures
) {

    public static FeedScheduleDto from(FeedSyncSchedule row, Instant nextRunAt) {
        return new FeedScheduleDto(
                row.isEnabled(),
                row.getCronExpression(),
                row.getLastRunAt(),
                row.getLastStatus(),
                row.getLastError(),
                nextRunAt,
                row.getConsecutiveFailures()
        );
    }

    public record UpdateRequest(
            @NotNull Boolean enabled,
            @NotBlank String cron
    ) {}
}

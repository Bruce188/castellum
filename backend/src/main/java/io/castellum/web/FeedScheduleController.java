package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.risk.FeedSyncSchedule;
import io.castellum.risk.FeedSyncScheduleRepository;
import io.castellum.web.dto.FeedScheduleDto;
import jakarta.validation.Valid;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.NoSuchElementException;

@RestController
@RequestMapping("/api/admin/feed-schedule")
public class FeedScheduleController {

    private final FeedSyncScheduleRepository repository;
    private final AuditService auditService;
    private final Clock clock;

    public FeedScheduleController(FeedSyncScheduleRepository repository,
                                   AuditService auditService,
                                   Clock clock) {
        this.repository = repository;
        this.auditService = auditService;
        this.clock = clock;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public FeedScheduleDto get() {
        FeedSyncSchedule row = repository.findById(FeedSyncSchedule.SINGLETON_ID)
                .orElseThrow(() -> new NoSuchElementException("feed_sync_schedule not found"));
        Instant nextRunAt = computeNextRunAt(row);
        return FeedScheduleDto.from(row, nextRunAt);
    }

    @PutMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public FeedScheduleDto update(@Valid @RequestBody FeedScheduleDto.UpdateRequest body,
                                   Authentication auth) {
        try {
            CronExpression.parse(body.cron());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid cron expression: " + e.getMessage());
        }

        FeedSyncSchedule row = repository.findById(FeedSyncSchedule.SINGLETON_ID)
                .orElseThrow(() -> new NoSuchElementException("feed_sync_schedule not found"));

        row.setEnabled(body.enabled());
        row.setCronExpression(body.cron());
        row.setUpdatedAt(clock.instant());
        repository.save(row);

        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        auditService.recordEvent(actor, "FEED_SCHEDULE_UPDATE", "feed_schedule",
                String.valueOf(FeedSyncSchedule.SINGLETON_ID),
                Map.of("enabled", row.isEnabled(), "cron", row.getCronExpression()));

        Instant nextRunAt = computeNextRunAt(row);
        return FeedScheduleDto.from(row, nextRunAt);
    }

    @PutMapping("/enable")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public FeedScheduleDto enable(Authentication auth) {
        FeedSyncSchedule row = repository.findById(FeedSyncSchedule.SINGLETON_ID)
                .orElseThrow(() -> new NoSuchElementException("feed_sync_schedule not found"));

        row.setEnabled(true);
        row.setUpdatedAt(clock.instant());
        repository.save(row);

        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        auditService.recordEvent(actor, "FEED_SCHEDULE_UPDATE", "feed_schedule",
                String.valueOf(FeedSyncSchedule.SINGLETON_ID),
                Map.of("enabled", true));

        Instant nextRunAt = computeNextRunAt(row);
        return FeedScheduleDto.from(row, nextRunAt);
    }

    @PutMapping("/disable")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public FeedScheduleDto disable(Authentication auth) {
        FeedSyncSchedule row = repository.findById(FeedSyncSchedule.SINGLETON_ID)
                .orElseThrow(() -> new NoSuchElementException("feed_sync_schedule not found"));

        row.setEnabled(false);
        row.setUpdatedAt(clock.instant());
        repository.save(row);

        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        auditService.recordEvent(actor, "FEED_SCHEDULE_UPDATE", "feed_schedule",
                String.valueOf(FeedSyncSchedule.SINGLETON_ID),
                Map.of("enabled", false));

        Instant nextRunAt = computeNextRunAt(row);
        return FeedScheduleDto.from(row, nextRunAt);
    }

    /**
     * Computes nextRunAt: min(cronNext, retryAfterAt) when a retry is pending,
     * else cronNext. Anchor is lastRunAt if set, otherwise clock.instant().
     */
    private Instant computeNextRunAt(FeedSyncSchedule row) {
        Instant base = row.getLastRunAt() != null ? row.getLastRunAt() : clock.instant();
        LocalDateTime anchorLdt = LocalDateTime.ofInstant(base, ZoneOffset.UTC);

        Instant cronNext = null;
        try {
            LocalDateTime next = CronExpression.parse(row.getCronExpression()).next(anchorLdt);
            if (next != null) {
                cronNext = next.toInstant(ZoneOffset.UTC);
            }
        } catch (IllegalArgumentException e) {
            // malformed cron — return null
        }

        Instant retryAfterAt = row.getRetryAfterAt();
        if (retryAfterAt != null && cronNext != null) {
            return retryAfterAt.isBefore(cronNext) ? retryAfterAt : cronNext;
        } else if (retryAfterAt != null) {
            return retryAfterAt;
        } else {
            return cronNext;
        }
    }
}

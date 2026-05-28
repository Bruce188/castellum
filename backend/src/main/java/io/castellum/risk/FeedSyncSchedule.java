package io.castellum.risk;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * Singleton durable-schedule row that carries the scheduled auto-pull's config,
 * last/next-run metadata, and retry state. One fixed row (id=1); no
 * {@code @GeneratedValue} — identity is managed by the migration seed.
 * Re-read every tick by {@link RiskFeedScheduler} → restart-safe by construction.
 */
@Entity
@Table(name = "feed_sync_schedule")
public class FeedSyncSchedule {

    public static final long SINGLETON_ID = 1L;

    @Id
    private Long id;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "cron_expression", nullable = false)
    private String cronExpression;

    @Column(name = "last_run_at")
    private Instant lastRunAt;

    @Column(name = "last_status")
    private String lastStatus;

    @Column(name = "last_error")
    private String lastError;

    @Column(name = "consecutive_failures", nullable = false)
    private int consecutiveFailures = 0;

    @Column(name = "retry_after_at")
    private Instant retryAfterAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    public FeedSyncSchedule() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getCronExpression() { return cronExpression; }
    public void setCronExpression(String cronExpression) { this.cronExpression = cronExpression; }

    public Instant getLastRunAt() { return lastRunAt; }
    public void setLastRunAt(Instant lastRunAt) { this.lastRunAt = lastRunAt; }

    public String getLastStatus() { return lastStatus; }
    public void setLastStatus(String lastStatus) { this.lastStatus = lastStatus; }

    public String getLastError() { return lastError; }
    public void setLastError(String lastError) { this.lastError = lastError; }

    public int getConsecutiveFailures() { return consecutiveFailures; }
    public void setConsecutiveFailures(int consecutiveFailures) { this.consecutiveFailures = consecutiveFailures; }

    public Instant getRetryAfterAt() { return retryAfterAt; }
    public void setRetryAfterAt(Instant retryAfterAt) { this.retryAfterAt = retryAfterAt; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}

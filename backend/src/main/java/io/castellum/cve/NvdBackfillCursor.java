package io.castellum.cve;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * Singleton durable cursor marking the resume point of an in-progress NVD FULL_BACKFILL.
 *
 * <p>One fixed row (id=1, seeded by migration V33); no {@code @GeneratedValue} — identity is
 * managed by the migration seed. {@code windowEnd} is the publish-date upper bound of the last
 * successfully-committed backfill window, or {@code null} when no backfill is in progress.
 *
 * <p>Read at {@link NvdSyncService#fullBackfillPull()} start and written after every committed
 * window, so a multi-hour historical backfill resumes where it stopped after a restart instead of
 * re-pulling from the configured start year — mirroring the per-chunk progress that
 * {@link io.castellum.scan.ScanExecutionService} persists on the scan row.
 */
@Entity
@Table(name = "nvd_backfill_cursor")
public class NvdBackfillCursor {

    public static final long SINGLETON_ID = 1L;

    @Id
    private Long id;

    @Column(name = "window_end")
    private Instant windowEnd;

    public NvdBackfillCursor() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Instant getWindowEnd() { return windowEnd; }
    public void setWindowEnd(Instant windowEnd) { this.windowEnd = windowEnd; }
}

package io.castellum.cve;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository for the singleton {@link NvdBackfillCursor} row
 * (id={@link NvdBackfillCursor#SINGLETON_ID}).
 */
public interface NvdBackfillCursorRepository extends JpaRepository<NvdBackfillCursor, Long> {
}

package io.castellum.risk;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class FeedSyncScheduleRepositoryTest {

    @Autowired
    private TestEntityManager em;

    @Autowired
    private FeedSyncScheduleRepository repo;

    @Test
    void save_findById_returnsRow() {
        FeedSyncSchedule entity = new FeedSyncSchedule();
        entity.setId(1L);
        entity.setEnabled(true);
        entity.setCronExpression("0 0 6 * * *");
        entity.setConsecutiveFailures(0);
        entity.setCreatedAt(Instant.now());

        repo.save(entity);

        var found = repo.findById(1L);
        assertThat(found).isPresent();
        assertThat(found.get().isEnabled()).isTrue();
        assertThat(found.get().getCronExpression()).isEqualTo("0 0 6 * * *");
        assertThat(found.get().getConsecutiveFailures()).isEqualTo(0);
    }

    @Test
    void defaults_roundTrip() {
        FeedSyncSchedule entity = new FeedSyncSchedule();
        entity.setId(1L);
        entity.setCronExpression("0 0 6 * * *");
        entity.setCreatedAt(Instant.now());

        repo.saveAndFlush(entity);
        em.clear();

        var reloaded = repo.findById(1L).orElseThrow();
        assertThat(reloaded.getConsecutiveFailures()).isEqualTo(0);
        assertThat(reloaded.isEnabled()).isTrue();
    }

    @Test
    void nullableColumns_persistWhenSet() {
        Instant lastRunAt = Instant.parse("2026-05-28T05:00:00Z");
        Instant retryAfterAt = Instant.parse("2026-05-28T06:05:00Z");
        Instant updatedAt = Instant.parse("2026-05-28T05:01:00Z");

        FeedSyncSchedule entity = new FeedSyncSchedule();
        entity.setId(1L);
        entity.setEnabled(true);
        entity.setCronExpression("0 0 6 * * *");
        entity.setCreatedAt(Instant.now());
        entity.setLastRunAt(lastRunAt);
        entity.setLastStatus("FAILED");
        entity.setLastError("connection refused");
        entity.setConsecutiveFailures(2);
        entity.setRetryAfterAt(retryAfterAt);
        entity.setUpdatedAt(updatedAt);

        repo.saveAndFlush(entity);
        em.clear();

        var reloaded = repo.findById(1L).orElseThrow();
        assertThat(reloaded.getLastRunAt()).isEqualTo(lastRunAt);
        assertThat(reloaded.getLastStatus()).isEqualTo("FAILED");
        assertThat(reloaded.getLastError()).isEqualTo("connection refused");
        assertThat(reloaded.getConsecutiveFailures()).isEqualTo(2);
        assertThat(reloaded.getRetryAfterAt()).isEqualTo(retryAfterAt);
        assertThat(reloaded.getUpdatedAt()).isEqualTo(updatedAt);
    }

    @Test
    void singletonId_isOne() {
        assertThat(FeedSyncSchedule.SINGLETON_ID).isEqualTo(1L);
    }
}

package io.castellum.risk;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

@Service
public class EpssUpsertService {
    private final EpssScoreRepository repo;

    public EpssUpsertService(EpssScoreRepository repo) { this.repo = repo; }

    @Transactional
    public void upsert(EpssRow row, LocalDate scoreDate, Instant ingestedAt) {
        var existing = repo.findByCveId(row.cveId());
        if (existing.isPresent()) {
            var e = existing.get();
            e.setEpss(BigDecimal.valueOf(row.epss()));
            e.setPercentile(BigDecimal.valueOf(row.percentile()));
            e.setScoreDate(scoreDate);
            e.setIngestedAt(ingestedAt);
            repo.save(e);
        } else {
            repo.save(new EpssScore(null, row.cveId(),
                BigDecimal.valueOf(row.epss()), BigDecimal.valueOf(row.percentile()),
                scoreDate, ingestedAt));
        }
    }
}

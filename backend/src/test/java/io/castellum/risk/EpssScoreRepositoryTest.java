package io.castellum.risk;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
class EpssScoreRepositoryTest {

    @Autowired
    private EpssScoreRepository repo;

    @Test
    void save_findByCveId_returnsRow() {
        EpssScore score = new EpssScore(null, "CVE-2020-15778",
            BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9), LocalDate.now(), Instant.now());
        repo.save(score);
        assertThat(repo.findByCveId("CVE-2020-15778")).isPresent();
    }

    @Test
    void unique_cveId_violationOnDuplicate() {
        repo.save(new EpssScore(null, "CVE-2020-15778",
            BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9), LocalDate.now(), Instant.now()));
        assertThatThrownBy(() -> {
            repo.save(new EpssScore(null, "CVE-2020-15778",
                BigDecimal.valueOf(0.6), BigDecimal.valueOf(0.8), LocalDate.now(), Instant.now()));
            repo.flush();
        }).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void findMaxScoreDate_returnsLatestDate() {
        LocalDate earlier = LocalDate.of(2026, 1, 1);
        LocalDate later = LocalDate.of(2026, 4, 29);
        repo.save(new EpssScore(null, "CVE-2020-15778",
            BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9), earlier, Instant.now()));
        repo.save(new EpssScore(null, "CVE-2021-44228",
            BigDecimal.valueOf(0.6), BigDecimal.valueOf(0.8), later, Instant.now()));
        assertThat(repo.findMaxScoreDate()).hasValue(later);
    }
}

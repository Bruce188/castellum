package io.castellum.risk;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

@Entity
@Table(name = "epss_score")
public class EpssScore {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", nullable = false, unique = true)
    private String cveId;

    @Column(nullable = false)
    private BigDecimal epss;

    @Column(nullable = false)
    private BigDecimal percentile;

    @Column(name = "score_date", nullable = false)
    private LocalDate scoreDate;

    @Column(name = "ingested_at")
    private Instant ingestedAt;

    public EpssScore() {}

    public EpssScore(Long id, String cveId, BigDecimal epss, BigDecimal percentile, LocalDate scoreDate, Instant ingestedAt) {
        this.id = id;
        this.cveId = cveId;
        this.epss = epss;
        this.percentile = percentile;
        this.scoreDate = scoreDate;
        this.ingestedAt = ingestedAt;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }

    public BigDecimal getEpss() { return epss; }
    public void setEpss(BigDecimal epss) { this.epss = epss; }

    public BigDecimal getPercentile() { return percentile; }
    public void setPercentile(BigDecimal percentile) { this.percentile = percentile; }

    public LocalDate getScoreDate() { return scoreDate; }
    public void setScoreDate(LocalDate scoreDate) { this.scoreDate = scoreDate; }

    public Instant getIngestedAt() { return ingestedAt; }
    public void setIngestedAt(Instant ingestedAt) { this.ingestedAt = ingestedAt; }
}

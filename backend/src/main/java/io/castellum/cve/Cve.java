package io.castellum.cve;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;

@Entity
@Table(name = "cve")
public class Cve {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", nullable = false, unique = true)
    private String cveId;

    @Column
    private Instant published;

    @Column(name = "last_modified", nullable = false)
    private Instant lastModified;

    @Column(name = "vuln_status")
    private String vulnStatus;

    @Column(columnDefinition = "text")
    private String description;

    @Column(name = "cvss_v31_score")
    private BigDecimal cvssV31Score;

    @Column(name = "cvss_v31_vector")
    private String cvssV31Vector;

    @Column(name = "cvss_v30_score")
    private BigDecimal cvssV30Score;

    @Column(name = "cvss_v30_vector")
    private String cvssV30Vector;

    @Column(name = "cvss_v2_score")
    private BigDecimal cvssV2Score;

    @Column(name = "cvss_v2_vector")
    private String cvssV2Vector;

    @Column(name = "raw_json", nullable = false, columnDefinition = "text")
    private String rawJson;

    @Column(name = "fetched_at")
    private Instant fetchedAt;

    public Cve() {}

    public Cve(Long id, String cveId, Instant published, Instant lastModified, String vulnStatus,
               String description, BigDecimal cvssV31Score, String cvssV31Vector,
               BigDecimal cvssV30Score, String cvssV30Vector, BigDecimal cvssV2Score,
               String cvssV2Vector, String rawJson, Instant fetchedAt) {
        this.id = id;
        this.cveId = cveId;
        this.published = published;
        this.lastModified = lastModified;
        this.vulnStatus = vulnStatus;
        this.description = description;
        this.cvssV31Score = cvssV31Score;
        this.cvssV31Vector = cvssV31Vector;
        this.cvssV30Score = cvssV30Score;
        this.cvssV30Vector = cvssV30Vector;
        this.cvssV2Score = cvssV2Score;
        this.cvssV2Vector = cvssV2Vector;
        this.rawJson = rawJson;
        this.fetchedAt = fetchedAt;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }

    public Instant getPublished() { return published; }
    public void setPublished(Instant published) { this.published = published; }

    public Instant getLastModified() { return lastModified; }
    public void setLastModified(Instant lastModified) { this.lastModified = lastModified; }

    public String getVulnStatus() { return vulnStatus; }
    public void setVulnStatus(String vulnStatus) { this.vulnStatus = vulnStatus; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public BigDecimal getCvssV31Score() { return cvssV31Score; }
    public void setCvssV31Score(BigDecimal cvssV31Score) { this.cvssV31Score = cvssV31Score; }

    public String getCvssV31Vector() { return cvssV31Vector; }
    public void setCvssV31Vector(String cvssV31Vector) { this.cvssV31Vector = cvssV31Vector; }

    public BigDecimal getCvssV30Score() { return cvssV30Score; }
    public void setCvssV30Score(BigDecimal cvssV30Score) { this.cvssV30Score = cvssV30Score; }

    public String getCvssV30Vector() { return cvssV30Vector; }
    public void setCvssV30Vector(String cvssV30Vector) { this.cvssV30Vector = cvssV30Vector; }

    public BigDecimal getCvssV2Score() { return cvssV2Score; }
    public void setCvssV2Score(BigDecimal cvssV2Score) { this.cvssV2Score = cvssV2Score; }

    public String getCvssV2Vector() { return cvssV2Vector; }
    public void setCvssV2Vector(String cvssV2Vector) { this.cvssV2Vector = cvssV2Vector; }

    public String getRawJson() { return rawJson; }
    public void setRawJson(String rawJson) { this.rawJson = rawJson; }

    public Instant getFetchedAt() { return fetchedAt; }
    public void setFetchedAt(Instant fetchedAt) { this.fetchedAt = fetchedAt; }
}

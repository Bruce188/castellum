package io.castellum.cve;

import jakarta.persistence.*;

@Entity
@Table(name = "cve_cpe_match")
public class CveCpeMatch {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_fk", nullable = false)
    private Long cveFk;

    @Column(name = "cpe23_uri", nullable = false)
    private String cpe23Uri;

    @Column(nullable = false)
    private Boolean vulnerable;

    @Column(name = "version_start_including")
    private String versionStartIncluding;

    @Column(name = "version_start_excluding")
    private String versionStartExcluding;

    @Column(name = "version_end_including")
    private String versionEndIncluding;

    @Column(name = "version_end_excluding")
    private String versionEndExcluding;

    public CveCpeMatch() {}

    public CveCpeMatch(Long id, Long cveFk, String cpe23Uri, Boolean vulnerable,
                       String versionStartIncluding, String versionStartExcluding,
                       String versionEndIncluding, String versionEndExcluding) {
        this.id = id;
        this.cveFk = cveFk;
        this.cpe23Uri = cpe23Uri;
        this.vulnerable = vulnerable;
        this.versionStartIncluding = versionStartIncluding;
        this.versionStartExcluding = versionStartExcluding;
        this.versionEndIncluding = versionEndIncluding;
        this.versionEndExcluding = versionEndExcluding;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getCveFk() { return cveFk; }
    public void setCveFk(Long cveFk) { this.cveFk = cveFk; }

    public String getCpe23Uri() { return cpe23Uri; }
    public void setCpe23Uri(String cpe23Uri) { this.cpe23Uri = cpe23Uri; }

    public Boolean getVulnerable() { return vulnerable; }
    public void setVulnerable(Boolean vulnerable) { this.vulnerable = vulnerable; }

    public String getVersionStartIncluding() { return versionStartIncluding; }
    public void setVersionStartIncluding(String versionStartIncluding) { this.versionStartIncluding = versionStartIncluding; }

    public String getVersionStartExcluding() { return versionStartExcluding; }
    public void setVersionStartExcluding(String versionStartExcluding) { this.versionStartExcluding = versionStartExcluding; }

    public String getVersionEndIncluding() { return versionEndIncluding; }
    public void setVersionEndIncluding(String versionEndIncluding) { this.versionEndIncluding = versionEndIncluding; }

    public String getVersionEndExcluding() { return versionEndExcluding; }
    public void setVersionEndExcluding(String versionEndExcluding) { this.versionEndExcluding = versionEndExcluding; }
}

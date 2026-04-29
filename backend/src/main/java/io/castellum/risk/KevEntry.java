package io.castellum.risk;

import jakarta.persistence.*;
import java.time.Instant;
import java.time.LocalDate;

@Entity
@Table(name = "kev_entry")
public class KevEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", nullable = false, unique = true)
    private String cveId;

    @Column(name = "vendor_project")
    private String vendorProject;

    private String product;

    @Column(name = "vulnerability_name")
    private String vulnerabilityName;

    @Column(name = "date_added", nullable = false)
    private LocalDate dateAdded;

    @Column(name = "short_description", columnDefinition = "text")
    private String shortDescription;

    @Column(name = "required_action", columnDefinition = "text")
    private String requiredAction;

    @Column(name = "due_date")
    private LocalDate dueDate;

    @Column(name = "known_ransomware_campaign_use")
    private String knownRansomwareCampaignUse;

    @Column(columnDefinition = "text")
    private String notes;

    @Column(columnDefinition = "text")
    private String cwes;

    @Column(name = "ingested_at")
    private Instant ingestedAt;

    public KevEntry() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }

    public String getVendorProject() { return vendorProject; }
    public void setVendorProject(String vendorProject) { this.vendorProject = vendorProject; }

    public String getProduct() { return product; }
    public void setProduct(String product) { this.product = product; }

    public String getVulnerabilityName() { return vulnerabilityName; }
    public void setVulnerabilityName(String vulnerabilityName) { this.vulnerabilityName = vulnerabilityName; }

    public LocalDate getDateAdded() { return dateAdded; }
    public void setDateAdded(LocalDate dateAdded) { this.dateAdded = dateAdded; }

    public String getShortDescription() { return shortDescription; }
    public void setShortDescription(String shortDescription) { this.shortDescription = shortDescription; }

    public String getRequiredAction() { return requiredAction; }
    public void setRequiredAction(String requiredAction) { this.requiredAction = requiredAction; }

    public LocalDate getDueDate() { return dueDate; }
    public void setDueDate(LocalDate dueDate) { this.dueDate = dueDate; }

    public String getKnownRansomwareCampaignUse() { return knownRansomwareCampaignUse; }
    public void setKnownRansomwareCampaignUse(String knownRansomwareCampaignUse) { this.knownRansomwareCampaignUse = knownRansomwareCampaignUse; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }

    public String getCwes() { return cwes; }
    public void setCwes(String cwes) { this.cwes = cwes; }

    public Instant getIngestedAt() { return ingestedAt; }
    public void setIngestedAt(Instant ingestedAt) { this.ingestedAt = ingestedAt; }
}

package io.castellum.risk;

import io.castellum.risk.dto.KevVulnerabilityDto;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.time.LocalDate;

@Service
public class KevUpsertService {
    private final KevEntryRepository repo;

    public KevUpsertService(KevEntryRepository repo) { this.repo = repo; }

    @Transactional
    public void upsert(KevVulnerabilityDto dto, Instant ingestedAt) {
        KevEntry entry = repo.findByCveId(dto.cveId()).orElseGet(KevEntry::new);
        entry.setCveId(dto.cveId());
        entry.setVendorProject(dto.vendorProject());
        entry.setProduct(dto.product());
        entry.setVulnerabilityName(dto.vulnerabilityName());
        entry.setDateAdded(LocalDate.parse(dto.dateAdded()));
        entry.setShortDescription(dto.shortDescription());
        entry.setRequiredAction(dto.requiredAction());
        entry.setDueDate(dto.dueDate() == null || dto.dueDate().isBlank() ? null : LocalDate.parse(dto.dueDate()));
        entry.setKnownRansomwareCampaignUse(dto.knownRansomwareCampaignUse());
        entry.setNotes(dto.notes());
        entry.setCwes(dto.cwes() == null ? null : String.join(",", dto.cwes()));
        entry.setIngestedAt(ingestedAt);
        repo.save(entry);
    }
}

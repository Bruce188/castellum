package io.castellum.threatintel;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditService;
import io.castellum.threatintel.misp.MispClient;
import io.castellum.threatintel.misp.MispPushResponse;
import io.castellum.threatintel.stix.StixBundle;
import io.castellum.threatintel.taxii.TaxiiClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
public class ThreatIntelService {

    private final BundleAssembler assembler;
    private final TaxiiClient taxiiClient;
    private final MispClient mispClient;
    private final AuditService auditService;
    private final ThreatIntelPushRepository pushRepository;
    private final ObjectMapper stixMapper;

    public ThreatIntelService(BundleAssembler assembler,
                              TaxiiClient taxiiClient,
                              MispClient mispClient,
                              AuditService auditService,
                              ThreatIntelPushRepository pushRepository,
                              @Qualifier("stixObjectMapper") ObjectMapper stixMapper) {
        this.assembler = assembler;
        this.taxiiClient = taxiiClient;
        this.mispClient = mispClient;
        this.auditService = auditService;
        this.pushRepository = pushRepository;
        this.stixMapper = stixMapper;
    }

    public ExportResult exportBundle() throws JsonProcessingException {
        StixBundle bundle = assembler.assemble();
        String json = stixMapper.writeValueAsString(bundle);
        AuditLog audit = recordAudit("EXPORT", bundle.id(), bundle.objects().size(), null);
        recordPush("EXPORT", bundle.id(), null, "in-memory", audit.getId());
        return new ExportResult(bundle.id(), bundle.objects().size(), json);
    }

    public TaxiiPushResult pushTaxii(String collectionOverride) throws IOException {
        StixBundle bundle = assembler.assemble();
        String json = stixMapper.writeValueAsString(bundle);
        int statusCode = taxiiClient.push(json, collectionOverride);
        AuditLog audit = recordAudit("PUSH_TAXII", bundle.id(), bundle.objects().size(),
            Map.of("collection", collectionOverride == null ? "" : collectionOverride));
        recordPush("TAXII", bundle.id(), statusCode, "status=" + statusCode, audit.getId());
        return new TaxiiPushResult(bundle.id(), bundle.objects().size(), statusCode);
    }

    public MispPushResult pushMisp() throws IOException {
        StixBundle bundle = assembler.assemble();
        MispPushResponse response = mispClient.push(bundle);
        String eventId = response.eventId();
        AuditLog audit = recordAudit("PUSH_MISP", bundle.id(), bundle.objects().size(),
            Map.of("misp_event_id", eventId == null ? "" : eventId));
        String excerpt = "misp_event_id=" + eventId;
        recordPush("MISP", bundle.id(), 200,
            excerpt.length() <= 256 ? excerpt : excerpt.substring(0, 256),
            audit.getId());
        return new MispPushResult(bundle.id(), eventId);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    AuditLog recordAudit(String action, String bundleId, int objectCount, Map<String, ?> extras) {
        var payload = new HashMap<String, Object>();
        payload.put("bundle_id", bundleId);
        payload.put("objects", objectCount);
        if (extras != null) payload.putAll(extras);
        return auditService.recordEvent("system", action, "stix_bundle", bundleId, payload);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void recordPush(String target, String bundleId, Integer statusCode, String excerpt, Long auditLogId) {
        String safeExcerpt = excerpt == null || excerpt.length() <= 256 ? excerpt : excerpt.substring(0, 256);
        var rec = new ThreatIntelPushRecord(target, bundleId, statusCode, safeExcerpt,
            Instant.now(), auditLogId);
        pushRepository.save(rec);
    }

    public record ExportResult(String bundleId, int objects, String json) {}
    public record TaxiiPushResult(String bundleId, int objects, int statusCode) {}
    public record MispPushResult(String bundleId, String mispEventId) {}
}

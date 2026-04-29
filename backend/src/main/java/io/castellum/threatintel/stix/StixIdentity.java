package io.castellum.threatintel.stix;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.OffsetDateTime;

public record StixIdentity(
    @JsonProperty("type") String type,
    @JsonProperty("spec_version") String specVersion,
    @JsonProperty("id") String id,
    @JsonProperty("created") OffsetDateTime created,
    @JsonProperty("modified") OffsetDateTime modified,
    @JsonProperty("name") String name,
    @JsonProperty("identity_class") String identityClass
) implements StixObject {
    public static StixIdentity castellum(String id, OffsetDateTime now) {
        return new StixIdentity("identity", "2.1", id, now, now, "Castellum", "system");
    }
}

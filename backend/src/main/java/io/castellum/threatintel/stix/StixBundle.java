package io.castellum.threatintel.stix;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record StixBundle(
    @JsonProperty("type") String type,
    @JsonProperty("id") String id,
    @JsonProperty("spec_version") String specVersion,
    @JsonProperty("objects") List<StixObject> objects
) {
    public static StixBundle of(String id, List<StixObject> objects) {
        return new StixBundle("bundle", id, "2.1", objects);
    }
}

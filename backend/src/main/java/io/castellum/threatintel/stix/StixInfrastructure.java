package io.castellum.threatintel.stix;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

public record StixInfrastructure(
    @JsonProperty("type") String type,
    @JsonProperty("spec_version") String specVersion,
    @JsonProperty("id") String id,
    @JsonProperty("created") OffsetDateTime created,
    @JsonProperty("modified") OffsetDateTime modified,
    @JsonProperty("created_by_ref") String createdByRef,
    @JsonProperty("name") String name,
    @JsonProperty("infrastructure_types") List<String> infrastructureTypes,
    @JsonProperty("extensions") Map<String, Map<String, Object>> extensions
) implements StixObject {}

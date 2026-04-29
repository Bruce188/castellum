package io.castellum.threatintel.stix;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.OffsetDateTime;

public record StixRelationship(
    @JsonProperty("type") String type,
    @JsonProperty("spec_version") String specVersion,
    @JsonProperty("id") String id,
    @JsonProperty("created") OffsetDateTime created,
    @JsonProperty("modified") OffsetDateTime modified,
    @JsonProperty("created_by_ref") String createdByRef,
    @JsonProperty("relationship_type") String relationshipType,
    @JsonProperty("source_ref") String sourceRef,
    @JsonProperty("target_ref") String targetRef
) implements StixObject {}

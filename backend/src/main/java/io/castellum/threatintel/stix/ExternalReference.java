package io.castellum.threatintel.stix;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ExternalReference(
    @JsonProperty("source_name") String sourceName,
    @JsonProperty("external_id") String externalId
) {}

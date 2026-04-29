package io.castellum.threatintel.misp;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MispAttribute(
    @JsonProperty("type") String type,
    @JsonProperty("category") String category,
    @JsonProperty("value") String value
) {}

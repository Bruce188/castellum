package io.castellum.threatintel.misp;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record MispEventEnvelope(@JsonProperty("Event") MispEvent event) {
    public record MispEvent(
        @JsonProperty("info") String info,
        @JsonProperty("distribution") String distribution,
        @JsonProperty("threat_level_id") String threatLevelId,
        @JsonProperty("analysis") String analysis,
        @JsonProperty("Attribute") List<MispAttribute> attributes
    ) {}
}

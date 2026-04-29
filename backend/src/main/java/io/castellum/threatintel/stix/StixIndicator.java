package io.castellum.threatintel.stix;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;

public record StixIndicator(
    @JsonProperty("type") String type,
    @JsonProperty("spec_version") String specVersion,
    @JsonProperty("id") String id,
    @JsonProperty("created") OffsetDateTime created,
    @JsonProperty("modified") OffsetDateTime modified,
    @JsonProperty("created_by_ref") String createdByRef,
    @JsonProperty("name") String name,
    @JsonProperty("indicator_types") List<String> indicatorTypes,
    @JsonProperty("pattern") String pattern,
    @JsonProperty("pattern_type") String patternType,
    @JsonProperty("valid_from") OffsetDateTime validFrom,
    @JsonProperty("x_castellum_composite_score") BigDecimal compositeScore
) implements StixObject {}

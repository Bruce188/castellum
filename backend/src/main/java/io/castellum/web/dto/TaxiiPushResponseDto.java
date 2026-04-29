package io.castellum.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record TaxiiPushResponseDto(
    @JsonProperty("status") String status,
    @JsonProperty("objects") int objects,
    @JsonProperty("bundle_id") String bundleId,
    @JsonProperty("status_code") int statusCode
) {}

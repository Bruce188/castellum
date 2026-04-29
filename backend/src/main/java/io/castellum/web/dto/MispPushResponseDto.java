package io.castellum.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MispPushResponseDto(
    @JsonProperty("status") String status,
    @JsonProperty("bundle_id") String bundleId,
    @JsonProperty("misp_event_id") String mispEventId
) {}

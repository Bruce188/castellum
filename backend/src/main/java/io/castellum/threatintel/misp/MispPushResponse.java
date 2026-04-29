package io.castellum.threatintel.misp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record MispPushResponse(@JsonProperty("Event") MispEventResponse event) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record MispEventResponse(@JsonProperty("id") String id) {}

    public String eventId() {
        return event != null ? event.id() : null;
    }
}

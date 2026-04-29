package io.castellum.cve.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.math.BigDecimal;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdCvssV30(NvdCvssV30Data cvssData) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record NvdCvssV30Data(BigDecimal baseScore, String vectorString) {}
}

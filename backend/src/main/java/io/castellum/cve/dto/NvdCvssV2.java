package io.castellum.cve.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.math.BigDecimal;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdCvssV2(NvdCvssV2Data cvssData) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record NvdCvssV2Data(BigDecimal baseScore, String vectorString) {}
}

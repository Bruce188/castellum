package io.castellum.cve.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.math.BigDecimal;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdCvssV31(NvdCvssV31Data cvssData) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record NvdCvssV31Data(BigDecimal baseScore, String vectorString) {}
}

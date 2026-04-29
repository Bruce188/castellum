package io.castellum.cve.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdMetrics(
        List<NvdCvssV31> cvssMetricV31,
        List<NvdCvssV30> cvssMetricV30,
        List<NvdCvssV2> cvssMetricV2) {}

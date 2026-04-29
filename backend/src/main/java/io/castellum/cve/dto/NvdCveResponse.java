package io.castellum.cve.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdCveResponse(
        int resultsPerPage,
        int startIndex,
        int totalResults,
        String format,
        String version,
        String timestamp,
        List<NvdVulnerability> vulnerabilities) {}

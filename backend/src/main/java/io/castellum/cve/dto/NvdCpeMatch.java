package io.castellum.cve.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdCpeMatch(
        String criteria,
        Boolean vulnerable,
        String versionStartIncluding,
        String versionStartExcluding,
        String versionEndIncluding,
        String versionEndExcluding,
        String matchCriteriaId) {}

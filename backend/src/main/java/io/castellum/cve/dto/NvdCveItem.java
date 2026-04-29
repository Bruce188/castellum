package io.castellum.cve.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdCveItem(
        String id,
        String published,
        String lastModified,
        String vulnStatus,
        List<NvdDescription> descriptions,
        NvdMetrics metrics,
        List<NvdConfiguration> configurations) {}

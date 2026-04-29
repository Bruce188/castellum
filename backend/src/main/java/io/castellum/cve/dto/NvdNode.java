package io.castellum.cve.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdNode(String operator, Boolean negate, List<NvdCpeMatch> cpeMatch) {}

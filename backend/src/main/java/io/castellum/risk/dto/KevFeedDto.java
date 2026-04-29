package io.castellum.risk.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record KevFeedDto(String title, String catalogVersion, String dateReleased,
                          int count, List<KevVulnerabilityDto> vulnerabilities) {}

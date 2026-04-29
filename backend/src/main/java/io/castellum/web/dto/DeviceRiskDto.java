package io.castellum.web.dto;

import java.math.BigDecimal;
import java.util.List;

public record DeviceRiskDto(long deviceId, BigDecimal score, List<String> topCveIds) {}

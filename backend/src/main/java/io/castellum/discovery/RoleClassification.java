package io.castellum.discovery;

/**
 * Immutable result of {@link DeviceRoleClassifier#classifyWithConfidence(io.castellum.domain.Device)},
 * carrying both the classified role and the confidence in that classification.
 *
 * @param role       the device role determined by the first-match rule chain
 * @param confidence {@link RoleConfidence#HIGH} for deterministic/API-confirmed rules;
 *                   {@link RoleConfidence#LOW} for heuristic rules with residual false-positive risk
 */
public record RoleClassification(DeviceRole role, RoleConfidence confidence) {
}

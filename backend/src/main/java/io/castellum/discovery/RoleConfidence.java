package io.castellum.discovery;

/**
 * Confidence level attached to a {@link DeviceRole} classification.
 *
 * <ul>
 *   <li>{@link #HIGH} — the role was determined by a deterministic, API-confirmed rule:
 *       a real Docker/k8s API reported this device as a container; OS fingerprinting gave a
 *       definitive server/desktop signal; or a well-known gateway topology places it as a router.
 *       The role is reliable enough to act on without further verification.</li>
 *   <li>{@link #LOW} — the role was inferred from a heuristic with known false-positive risk.
 *       The primary example is the macvlan/ipvlan sweep rule: a MAC OUI of {@code 02:42:*}
 *       (the Docker bridge locally-administered OUI) plus behavioural signals suggests a container,
 *       but real hardware with a locally-administered OUI would be misclassified. Treat LOW roles
 *       as advisory; do not use them as the sole basis for high-impact decisions.</li>
 * </ul>
 */
public enum RoleConfidence {
    HIGH,
    LOW
}

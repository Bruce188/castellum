package io.castellum.web.dto;

/**
 * Read-only DTO for {@code GET /api/discovery/sources}. Reports the configured availability
 * of each {@link io.castellum.discovery.DiscoverySource} so operators can confirm — without
 * dispatching a sweep — which probes will fire.
 *
 * <p>The {@code enabled} flag reflects build-time wiring and runtime feature flags only.
 * It does not promise the underlying capability (e.g. {@code CAP_NET_RAW}) is granted at
 * the OS layer; an actual sweep may still throw {@link io.castellum.discovery.DiscoveryUnavailableException}.
 *
 * <p>{@code description} is optional and may be {@code null}.
 */
public record DiscoverySourceDto(
    String source,
    boolean enabled,
    String description
) {}

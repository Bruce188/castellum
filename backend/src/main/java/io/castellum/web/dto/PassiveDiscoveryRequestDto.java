package io.castellum.web.dto;

import io.castellum.discovery.DiscoverySource;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;

import java.util.List;

/**
 * Controller-side DTO for {@code POST /api/discovery/passive}.
 * Uses relaxed validation to allow defaults:
 * <ul>
 *   <li>{@code durationSeconds == 0} means "use default (30)".</li>
 *   <li>{@code sources == null or empty} means "use default [ARP, MDNS]".</li>
 * </ul>
 * The controller normalizes these and constructs the strict
 * {@link io.castellum.discovery.PassiveDiscoveryRequest} for the service.
 */
public record PassiveDiscoveryRequestDto(
    @Pattern(regexp = "^[a-zA-Z0-9_:.\\-]{1,16}$",
             message = "iface must be 1..16 chars from [a-zA-Z0-9_:.-]",
             flags = Pattern.Flag.CASE_INSENSITIVE)
    String iface,

    @Min(0) @Max(300)
    int durationSeconds,

    List<DiscoverySource> sources
) {}

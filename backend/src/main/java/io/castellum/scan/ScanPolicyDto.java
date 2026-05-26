package io.castellum.scan;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;

/**
 * DTO for /api/scan-policy create + list responses. Mirrors {@link ScanPolicy}
 * but lets us evolve the wire shape independently from the JPA entity.
 */
public class ScanPolicyDto {

    /** Request body. */
    public record CreateRequest(
            @NotBlank @Size(min = 1, max = 64)
            @Pattern(regexp = "[A-Za-z0-9 ._-]+",
                    message = "name must contain only letters, digits, space, dot, underscore, or hyphen")
            String name,
            @NotBlank String cronExpression,
            @NotBlank String cidr,
            @NotBlank String scanType,
            Boolean enabled) {}

    /** Response body. */
    public record Response(
            Long id,
            String name,
            String cronExpression,
            String cidr,
            String scanType,
            boolean enabled,
            Instant createdAt,
            Instant lastTriggeredAt) {

        public static Response from(ScanPolicy p) {
            return new Response(
                p.getId(),
                p.getName(),
                p.getCronExpression(),
                p.getCidr(),
                p.getScanType(),
                p.isEnabled(),
                p.getCreatedAt(),
                p.getLastTriggeredAt()
            );
        }
    }
}

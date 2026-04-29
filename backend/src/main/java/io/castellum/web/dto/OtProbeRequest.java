package io.castellum.web.dto;

import io.castellum.ot.OtProtocol;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Request body for {@code POST /api/ot-probe}.
 *
 * @param host     IPv4 address of the OT target (dotted-quad, no hostname or IPv6)
 * @param port     TCP/UDP port (1–65535)
 * @param protocol one of the four supported OT protocols
 */
public record OtProbeRequest(
    @NotBlank String host,
    @NotNull @Min(1) @Max(65535) Integer port,
    @NotNull OtProtocol protocol
) {}

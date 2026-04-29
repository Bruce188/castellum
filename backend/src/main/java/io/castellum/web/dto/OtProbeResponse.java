package io.castellum.web.dto;

import io.castellum.ot.OtProtocol;

import java.time.Instant;
import java.util.Map;

/**
 * Response body for a successful {@code POST /api/ot-probe}.
 *
 * @param host        IPv4 address of the probed target
 * @param port        port that was probed
 * @param protocol    OT protocol used for the probe
 * @param vendor      decoded vendor name (may be null if not found)
 * @param product     decoded product name / model (may be null)
 * @param version     decoded firmware/software version (may be null)
 * @param rawFields   all decoded protocol-native fields (numeric key → string for Modbus; name → value for others)
 * @param deviceId    ID of the device row in the inventory
 * @param serviceId   ID of the network-service row that was upserted
 * @param observedAt  timestamp of the successful probe
 */
public record OtProbeResponse(
    String host,
    int port,
    OtProtocol protocol,
    String vendor,
    String product,
    String version,
    Map<String, String> rawFields,
    long deviceId,
    long serviceId,
    Instant observedAt
) {}

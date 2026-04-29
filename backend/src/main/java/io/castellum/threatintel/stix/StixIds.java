package io.castellum.threatintel.stix;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** Deterministic STIX SDO ID generator. */
public final class StixIds {

    public static final String IDENTITY_ID = "identity--" + seed("castellum:identity:root");

    private StixIds() {}

    public static String forDevice(String ipAddress) {
        return "infrastructure--" + seed("castellum:infrastructure:" + ipAddress);
    }

    public static String forCve(String cveId) {
        return "vulnerability--" + seed("castellum:vulnerability:" + cveId);
    }

    public static String forIndicator(String cveId, String ipAddress) {
        return "indicator--" + seed("castellum:indicator:" + cveId + ":" + ipAddress);
    }

    public static String forRelationship(String relType, String sourceRef, String targetRef) {
        return "relationship--" + seed("castellum:relationship:" + relType + ":" + sourceRef + ":" + targetRef);
    }

    /** Random v4 — bundle envelope is intentionally non-deterministic per push moment. */
    public static String forBundle() {
        return "bundle--" + UUID.randomUUID();
    }

    private static String seed(String input) {
        return UUID.nameUUIDFromBytes(input.getBytes(StandardCharsets.UTF_8)).toString();
    }
}

/**
 * Hand-built STIX 2.1 model.
 *
 * Deterministic SDO IDs use {@link java.util.UUID#nameUUIDFromBytes} (RFC 4122 v3 / MD5).
 * STIX 2.1 §3.1 accepts any RFC 4122 variant; published examples favor v5 (SHA-1).
 * v3 is intentional here — pulling a v5 dependency for cosmetic alignment is not justified.
 *
 * Field naming is snake-case via {@code @JsonProperty} per STIX 2.1 contract.
 * Z-suffix timestamp formatting via {@link io.castellum.threatintel.stix.StixZuluOffsetDateTimeSerializer}.
 */
package io.castellum.threatintel.stix;

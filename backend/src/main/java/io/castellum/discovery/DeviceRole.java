package io.castellum.discovery;

/**
 * Explicit classification of a discovered device's functional role.
 *
 * <p>Populated at upsert time by {@link DeviceRoleClassifier}. The default value for all
 * existing rows and any row whose signals are ambiguous is {@link #UNKNOWN}.
 *
 * <p>{@link #LAPTOP} is reserved. OS fingerprinting alone cannot reliably distinguish a
 * laptop from a desktop (the kernel advertises no chassis type), so ambiguous desktop-class
 * OSes deterministically map to {@link #DESKTOP}. A future signal (e.g. mDNS model hint,
 * SNMP chassis OID) may promote rows to {@code LAPTOP} without a schema change.
 */
public enum DeviceRole {
    LAPTOP,
    DESKTOP,
    SERVER,
    ROUTER,
    CONTAINER,
    UNKNOWN
}

package io.castellum.discovery;

/**
 * Authoritative role evidence extracted from passive payload sources:
 * DHCP option announcements and mDNS {@code _device-info} chassis models.
 *
 * <p>Threaded {@code DiscoveredNeighbor → Discovery → Device → DeviceRoleClassifier}.
 * A single STRING-mapped enum column ({@code role_hint}, nullable) is used instead of
 * per-hint booleans: one Flyway column, one merge rule, trivially extensible.
 *
 * <p>{@link #rank(RoleHint)} defines the single total order that drives every
 * merge / sticky-upgrade decision: incoming null (rank 0) never clears, equal rank
 * keeps the existing value, higher rank upgrades.
 */
public enum RoleHint {

    /** DHCP option 3 names this IP as default router → ROUTER @ HIGH. Rank 5. */
    GATEWAY,

    /** DHCP option 54 (server identifier) in a BOOTREPLY → SERVER @ HIGH. Rank 4. */
    DHCP_SERVER,

    /** DHCP option 6 names this IP as resolver → SERVER @ HIGH. Rank 3. */
    DNS_SERVER,

    /** mDNS {@code _device-info} TXT {@code model=MacBook*} → LAPTOP @ HIGH. Rank 2. */
    LAPTOP_CHASSIS,

    /** mDNS {@code _device-info} TXT model iMac / Macmini / MacPro prefixes → DESKTOP @ HIGH. Rank 1. */
    DESKTOP_CHASSIS;

    /**
     * Total-order rank for merge decisions: 0 for {@code null}, else
     * GATEWAY=5, DHCP_SERVER=4, DNS_SERVER=3, LAPTOP_CHASSIS=2, DESKTOP_CHASSIS=1.
     */
    public static int rank(RoleHint h) {
        if (h == null) {
            return 0;
        }
        return switch (h) {
            case GATEWAY -> 5;
            case DHCP_SERVER -> 4;
            case DNS_SERVER -> 3;
            case LAPTOP_CHASSIS -> 2;
            case DESKTOP_CHASSIS -> 1;
        };
    }
}

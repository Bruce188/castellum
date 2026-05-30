package io.castellum.discovery.probe;

import io.castellum.discovery.DockerContainer.DockerNetworkAttachment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps SNMP interface + IP address rows to synthetic docker bridge gateway attachments.
 *
 * <p>Filters to docker-style bridge interfaces (docker0, br-*, veth*) and joins with IP address
 * rows to produce {@link DockerNetworkAttachment} records carrying only the gateway IP —
 * SUBNETS-ONLY, no container IP. The {@code containerIp} field is always {@code null}.
 *
 * <p>Malformed or unrecognisable rows are skipped (malformed-tolerant). Non-bridge interfaces
 * (eth0, lo, etc.) are excluded.
 */
@Component
public class SnmpBridgeMapper {

    /**
     * Map SNMP interface rows + IP address rows to gateway-only docker bridge attachments.
     *
     * <p>Only interfaces whose {@code ifDescr} or {@code ifName} matches docker bridge patterns
     * (docker0, br-*, veth*) are included. For each matching interface, the corresponding IP
     * address row is looked up by {@code ifIndex}. The result is a gateway-only attachment
     * with {@code containerIp == null}.
     *
     * @param ifaceRows interface rows from {@link SnmpClient#walkInterfaces}
     * @param addrRows  IP address rows from {@link SnmpClient#walkIpAddresses}
     * @return list of gateway-only docker network attachments (containerIp always null)
     */
    public List<DockerNetworkAttachment> mapBridges(List<SnmpClient.SnmpRow> ifaceRows,
                                                    List<SnmpClient.SnmpAddr> addrRows) {
        if (ifaceRows == null || ifaceRows.isEmpty()) return List.of();

        // Build ifIndex → IP map from address rows
        Map<Integer, String> ipByIfIndex = new HashMap<>();
        if (addrRows != null) {
            for (SnmpClient.SnmpAddr addr : addrRows) {
                if (addr.ipAddress() != null && !addr.ipAddress().isBlank()) {
                    ipByIfIndex.putIfAbsent(addr.ifIndex(), addr.ipAddress());
                }
            }
        }

        List<DockerNetworkAttachment> result = new ArrayList<>();
        for (SnmpClient.SnmpRow row : ifaceRows) {
            try {
                String name = effectiveName(row);
                if (!isBridgeInterface(name)) continue;

                String bridgeIp = ipByIfIndex.get(row.ifIndex());
                if (bridgeIp == null || bridgeIp.isBlank()) continue;

                // Gateway-only: containerIp = null, networkName = "snmp-bridge:" + ifName
                result.add(new DockerNetworkAttachment("snmp-bridge:" + name, null, bridgeIp));
            } catch (Exception e) {
                // Malformed row — skip (malformed-tolerant)
            }
        }
        return result;
    }

    /**
     * Returns the effective interface name: ifName if non-blank, else ifDescr.
     */
    private static String effectiveName(SnmpClient.SnmpRow row) {
        String name = row.ifName();
        if (name != null && !name.isBlank()) return name.trim();
        name = row.ifDescr();
        if (name != null && !name.isBlank()) return name.trim();
        return "";
    }

    /**
     * Returns true if the interface name matches docker bridge patterns:
     * docker0, br-*, veth*.
     */
    static boolean isBridgeInterface(String name) {
        if (name == null || name.isBlank()) return false;
        return name.equals("docker0")
            || name.startsWith("br-")
            || name.startsWith("veth");
    }
}

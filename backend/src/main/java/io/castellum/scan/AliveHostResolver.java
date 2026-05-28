package io.castellum.scan;

import io.castellum.domain.DeviceRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Resolves the set of "alive" host addresses within a CIDR so that port-enumerating scans
 * (notably SERVICE_DETECT) can target only real hosts instead of every address in the range.
 *
 * <p><b>Source.</b> The chosen source is the persisted {@code Device} inventory filtered to
 * IPs that fall within the requested CIDR. In the unified-scan flow PING_SWEEP runs first and
 * upserts every responding host into this inventory (via {@code DeviceUpsertService}), so by
 * the time SERVICE_DETECT runs the inventory is the live set for the CIDR. This is the
 * "persisted devices whose IP ∈ CIDR" fallback named in the design: it is preferred over
 * re-deriving hosts from the most-recent PING_SWEEP scan row because PING_SWEEP does not
 * persist a per-scan host list — it only upserts devices — and a device-IP filter captures
 * both newly-discovered and previously-known live hosts without a brittle time-window join.
 *
 * <p>IPv4-in-CIDR membership is computed in-process via {@link CidrValidator#cidrContainsHost}
 * because it is not portably expressible in JPQL. The device inventory is bounded
 * ({@code castellum.graph.max-devices}, default 1024) so the full-IP fetch is cheap.
 */
@Service
public class AliveHostResolver {

    private final DeviceRepository deviceRepository;

    public AliveHostResolver(DeviceRepository deviceRepository) {
        this.deviceRepository = deviceRepository;
    }

    /**
     * Returns the distinct, validated host IPs known to live within {@code cidr}. Order follows
     * the repository's iteration order; duplicates and addresses outside the CIDR are dropped.
     * An empty result means no alive hosts are known — the caller should short-circuit rather
     * than fall back to scanning the whole range.
     *
     * @param cidr the validated scan CIDR
     * @return possibly-empty list of alive host IP strings within the CIDR
     */
    public List<String> aliveHostsIn(String cidr) {
        List<String> result = new ArrayList<>();
        for (String ip : deviceRepository.findAllIpAddresses()) {
            if (ip != null
                && CidrValidator.cidrContainsHost(cidr, ip)
                && !result.contains(ip)) {
                result.add(ip);
            }
        }
        return result;
    }
}

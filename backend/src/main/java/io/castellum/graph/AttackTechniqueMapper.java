package io.castellum.graph;

import io.castellum.domain.NetworkService;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Static, immutable mapping of {@link EdgeType} → {@link AttackTechnique}. Default mapping per
 * type (single technique). The {@link #forEdgeType(EdgeType, NetworkService)} overload refines
 * EXPLOITABLE_VULN to T1210 (Exploitation of Remote Services) when the service name matches
 * SMB / RPC / RDP / SSH; otherwise it falls back to the default T1190 mapping.
 *
 * <p>The mapping is a published contract; mutation throws {@link UnsupportedOperationException}.
 */
public final class AttackTechniqueMapper {

    public static final Map<EdgeType, AttackTechnique> MAPPING;

    private static final AttackTechnique T1210 =
        new AttackTechnique("T1210", "Exploitation of Remote Services");

    static {
        Map<EdgeType, AttackTechnique> m = new HashMap<>();
        m.put(EdgeType.SAME_SUBNET, new AttackTechnique("T1021", "Remote Services"));
        m.put(EdgeType.EXPLOITABLE_VULN, new AttackTechnique("T1190", "Exploit Public-Facing Application"));
        m.put(EdgeType.WEAK_CRED_PATH, new AttackTechnique("T1078", "Valid Accounts"));
        m.put(EdgeType.GATEWAY_PIVOT, new AttackTechnique("T1090", "Proxy"));
        MAPPING = Map.copyOf(m);
    }

    private AttackTechniqueMapper() {
        throw new UnsupportedOperationException("static utility");
    }

    public static AttackTechnique forEdgeType(EdgeType type) {
        AttackTechnique t = MAPPING.get(type);
        if (t == null) throw new IllegalArgumentException("no technique mapping for " + type);
        return t;
    }

    /**
     * Service-aware overload. Returns T1210 (Exploitation of Remote Services) for
     * EXPLOITABLE_VULN edges when the service name matches SMB / RPC / RDP / SSH; otherwise
     * delegates to {@link #forEdgeType(EdgeType)}.
     */
    public static AttackTechnique forEdgeType(EdgeType type, NetworkService service) {
        if (type == EdgeType.EXPLOITABLE_VULN && service != null && service.getName() != null) {
            String n = service.getName().toLowerCase(Locale.ROOT);
            if (n.contains("smb") || n.contains("rpc") || n.contains("rdp") || n.contains("ssh")) {
                return T1210;
            }
        }
        return forEdgeType(type);
    }

    /**
     * Resolve the human-readable technique name for a technique id captured at edge build time
     * (see {@link AttackEdge#getTechniqueId()}). Recognises the registered ids for the default
     * EdgeType mapping plus the T1210 service-aware override; for any unrecognised id, falls
     * back to the name from the EdgeType-only default mapping.
     */
    public static String nameFor(String techniqueId, EdgeType fallbackType) {
        if (techniqueId == null) return forEdgeType(fallbackType).name();
        if (T1210.id().equals(techniqueId)) return T1210.name();
        for (AttackTechnique t : MAPPING.values()) {
            if (t.id().equals(techniqueId)) return t.name();
        }
        return forEdgeType(fallbackType).name();
    }
}

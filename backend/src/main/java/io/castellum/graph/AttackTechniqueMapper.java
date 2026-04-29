package io.castellum.graph;

import java.util.HashMap;
import java.util.Map;

/**
 * Static, immutable mapping of {@link EdgeType} → {@link AttackTechnique}. Single technique per type
 * in v1. Refinement (e.g. SMB/RPC EXPLOITABLE_VULN → T1210 instead of T1190) is deferred — see
 * {@code progress.md} Deferred entry "EXPLOITABLE_VULN technique granularity".
 *
 * <p>The mapping is a published contract; mutation throws {@link UnsupportedOperationException}.
 */
public final class AttackTechniqueMapper {

    public static final Map<EdgeType, AttackTechnique> MAPPING;

    static {
        Map<EdgeType, AttackTechnique> m = new HashMap<>();
        m.put(EdgeType.SAME_SUBNET, new AttackTechnique("T1021", "Remote Services"));
        m.put(EdgeType.EXPLOITABLE_VULN, new AttackTechnique("T1190", "Exploit Public-Facing Application"));
        m.put(EdgeType.WEAK_CRED_PATH, new AttackTechnique("T1078", "Valid Accounts"));
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
}

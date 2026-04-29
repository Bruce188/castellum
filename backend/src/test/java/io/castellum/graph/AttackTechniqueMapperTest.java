package io.castellum.graph;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AttackTechniqueMapperTest {

    @Test
    void sameSubnetMapsToT1021RemoteServices() {
        AttackTechnique t = AttackTechniqueMapper.forEdgeType(EdgeType.SAME_SUBNET);
        assertThat(t.id()).isEqualTo("T1021");
        assertThat(t.name()).isEqualTo("Remote Services");
    }

    @Test
    void exploitableVulnMapsToT1190ExploitPublicFacingApplication() {
        AttackTechnique t = AttackTechniqueMapper.forEdgeType(EdgeType.EXPLOITABLE_VULN);
        assertThat(t.id()).isEqualTo("T1190");
        assertThat(t.name()).isEqualTo("Exploit Public-Facing Application");
    }

    @Test
    void weakCredPathMapsToT1078ValidAccounts() {
        AttackTechnique t = AttackTechniqueMapper.forEdgeType(EdgeType.WEAK_CRED_PATH);
        assertThat(t.id()).isEqualTo("T1078");
        assertThat(t.name()).isEqualTo("Valid Accounts");
    }

    @Test
    void mappingIsImmutable() {
        assertThatThrownBy(() ->
            AttackTechniqueMapper.MAPPING.put(EdgeType.SAME_SUBNET, new AttackTechnique("T9999", "fake"))
        ).isInstanceOf(UnsupportedOperationException.class);
    }
}

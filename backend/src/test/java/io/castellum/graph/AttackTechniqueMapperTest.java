package io.castellum.graph;

import io.castellum.domain.NetworkService;
import org.junit.jupiter.api.Test;

import java.time.Instant;

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

    @Test
    void exploitableVulnWithSshServiceMapsToT1210() {
        NetworkService svc = new NetworkService(null, 1L, 22, "tcp", "openssh", "8.2", Instant.EPOCH);
        AttackTechnique t = AttackTechniqueMapper.forEdgeType(EdgeType.EXPLOITABLE_VULN, svc);
        assertThat(t.id()).isEqualTo("T1210");
        assertThat(t.name()).isEqualTo("Exploitation of Remote Services");
    }

    @Test
    void exploitableVulnWithHttpServiceFallsBackToT1190() {
        NetworkService svc = new NetworkService(null, 1L, 80, "tcp", "nginx", "1.18", Instant.EPOCH);
        AttackTechnique t = AttackTechniqueMapper.forEdgeType(EdgeType.EXPLOITABLE_VULN, svc);
        assertThat(t.id()).isEqualTo("T1190");
    }

    @Test
    void exploitableVulnWithNullServiceFallsBackToT1190() {
        AttackTechnique t = AttackTechniqueMapper.forEdgeType(EdgeType.EXPLOITABLE_VULN, null);
        assertThat(t.id()).isEqualTo("T1190");
    }
}

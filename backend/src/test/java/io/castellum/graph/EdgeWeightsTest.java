package io.castellum.graph;

import io.castellum.risk.RiskScore;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.data.Offset.offset;

class EdgeWeightsTest {

    private static RiskScore score(String composite) {
        BigDecimal v = new BigDecimal(composite);
        return new RiskScore(v, BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO);
    }

    @Test
    void sameSubnetWeightIsConstant1() {
        assertThat(EdgeWeights.sameSubnetWeight()).isEqualTo(1.0);
    }

    @Test
    void sameSubnetRiskIsZero() {
        assertThat(EdgeWeights.sameSubnetRisk()).isEqualTo(0.0);
    }

    @Test
    void weakCredPathWeightIsConstant2() {
        assertThat(EdgeWeights.weakCredPathWeight()).isEqualTo(2.0);
    }

    @Test
    void weakCredPathRiskIsConstant5() {
        assertThat(EdgeWeights.weakCredPathRisk()).isEqualTo(5.0);
    }

    @Test
    void vulnEdgeWeightInvertsCompositeScore() {
        // composite=9.5 → weight = 11.0 - 9.5 = 1.5
        assertThat(EdgeWeights.exploitableVulnWeight(score("9.5"))).isCloseTo(1.5, offset(1e-9));
    }

    @Test
    void vulnEdgeWeightFloorIsOnePointZero() {
        // composite=10.0 → weight = 11.0 - 10.0 = 1.0
        assertThat(EdgeWeights.exploitableVulnWeight(score("10.0"))).isCloseTo(1.0, offset(1e-9));
    }

    @Test
    void vulnEdgeRiskEqualsCompositeScore() {
        // composite=9.5 → riskContribution = 9.5
        assertThat(EdgeWeights.exploitableVulnRisk(score("9.5"))).isCloseTo(9.5, offset(1e-9));
    }

    @Test
    void vulnEdgeWeightForZeroComposite() {
        // composite=0.0 → weight = 11.0 - 0.0 = 11.0
        assertThat(EdgeWeights.exploitableVulnWeight(score("0.0"))).isCloseTo(11.0, offset(1e-9));
    }

    @Test
    void gatewayPivotWeightIsConstant3() {
        assertThat(EdgeWeights.gatewayPivotWeight()).isEqualTo(3.0);
    }

    @Test
    void gatewayPivotRiskIsConstant4() {
        assertThat(EdgeWeights.gatewayPivotRisk()).isEqualTo(4.0);
    }

    @Test
    void gatewayPivotWeightIsHeavierThanSameSubnet() {
        assertThat(EdgeWeights.gatewayPivotWeight()).isGreaterThan(EdgeWeights.sameSubnetWeight());
    }
}

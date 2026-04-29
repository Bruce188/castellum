package io.castellum.risk;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RiskInputsTest {

    @Test
    void validInputs_construct() {
        RiskInputs inputs = new RiskInputs(0.5, 0.5, true, Criticality.HIGH);
        assertThat(inputs.cvssNormalized()).isEqualTo(0.5);
        assertThat(inputs.epss()).isEqualTo(0.5);
        assertThat(inputs.kev()).isTrue();
        assertThat(inputs.criticality()).isEqualTo(Criticality.HIGH);
    }

    @Test
    void cvssNormalizedOutOfRange_throws() {
        assertThatThrownBy(() -> new RiskInputs(-0.1, 0.5, false, Criticality.MEDIUM))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RiskInputs(1.1, 0.5, false, Criticality.MEDIUM))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void epssOutOfRange_throws() {
        assertThatThrownBy(() -> new RiskInputs(0.5, -0.1, false, Criticality.MEDIUM))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RiskInputs(0.5, 1.1, false, Criticality.MEDIUM))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void nullCriticality_throws() {
        assertThatThrownBy(() -> new RiskInputs(0.5, 0.5, false, null))
            .isInstanceOf(IllegalArgumentException.class);
    }
}

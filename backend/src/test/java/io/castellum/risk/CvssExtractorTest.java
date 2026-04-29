package io.castellum.risk;

import io.castellum.cve.Cve;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class CvssExtractorTest {

    @Test
    void normalized_v31Only_returnsScoreDividedByTen() {
        Cve cve = new Cve();
        cve.setCvssV31Score(new BigDecimal("9.8"));
        assertThat(CvssExtractor.normalized(cve)).isCloseTo(0.98, within(1e-9));
    }

    @Test
    void normalized_v30Only_returnsScoreDividedByTen() {
        Cve cve = new Cve();
        cve.setCvssV30Score(new BigDecimal("7.5"));
        assertThat(CvssExtractor.normalized(cve)).isCloseTo(0.75, within(1e-9));
    }

    @Test
    void normalized_v2Only_returnsScoreDividedByTen() {
        Cve cve = new Cve();
        cve.setCvssV2Score(new BigDecimal("4.3"));
        assertThat(CvssExtractor.normalized(cve)).isCloseTo(0.43, within(1e-9));
    }

    @Test
    void normalized_allThree_picksMax() {
        Cve cve = new Cve();
        cve.setCvssV31Score(new BigDecimal("5.5"));
        cve.setCvssV30Score(new BigDecimal("9.1"));
        cve.setCvssV2Score(new BigDecimal("7.0"));
        assertThat(CvssExtractor.normalized(cve)).isCloseTo(0.91, within(1e-9));
    }

    @Test
    void normalized_allNull_returnsZero() {
        Cve cve = new Cve();
        assertThat(CvssExtractor.normalized(cve)).isEqualTo(0.0);
    }

    @Test
    void normalized_negativeSignumTreatedAsMissing() {
        Cve cve = new Cve();
        cve.setCvssV31Score(new BigDecimal("-1.0"));
        cve.setCvssV30Score(new BigDecimal("6.0"));
        assertThat(CvssExtractor.normalized(cve)).isCloseTo(0.6, within(1e-9));
    }
}

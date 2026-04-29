package io.castellum.risk;

import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.time.LocalDate;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EpssCsvParserTest {

    @Test
    void parse_skipsCommentLineAndHeader_capturesScoreDate() throws Exception {
        String csv = """
            #model_version:v1,score_date:2026-04-29T00:00:00Z
            cve,epss,percentile
            CVE-2020-15778,0.97564,0.99811
            """;
        var result = EpssCsvParser.parse(new StringReader(csv));
        assertThat(result.rows()).hasSize(1);
        assertThat(result.rows().get(0).epss()).isCloseTo(0.97564, org.assertj.core.data.Offset.offset(1e-5));
        assertThat(result.scoreDate()).isEqualTo(LocalDate.of(2026, 4, 29));
    }

    @Test
    void parse_handlesMultipleRows() throws Exception {
        String csv = """
            #score_date:2026-04-29T00:00:00Z
            cve,epss,percentile
            CVE-0001,0.1,0.2
            CVE-0002,0.2,0.3
            CVE-0003,0.3,0.4
            CVE-0004,0.4,0.5
            CVE-0005,0.5,0.6
            """;
        var result = EpssCsvParser.parse(new StringReader(csv));
        assertThat(result.rows()).hasSize(5);
    }

    @Test
    void parse_skipsMalformedRowAndContinues() throws Exception {
        String csv = """
            #score_date:2026-04-29T00:00:00Z
            cve,epss,percentile
            CVE-0001,0.1,0.2
            BAD-ROW,not-a-number,whatever
            CVE-0003,0.3,0.4
            """;
        var result = EpssCsvParser.parse(new StringReader(csv));
        assertThat(result.rows()).hasSize(2);
    }

    @Test
    void parse_handlesEmptyAfterHeader() throws Exception {
        String csv = """
            #score_date:2026-04-29T00:00:00Z
            cve,epss,percentile
            """;
        var result = EpssCsvParser.parse(new StringReader(csv));
        assertThat(result.rows()).isEmpty();
    }

    @Test
    void parse_rejectsMissingHeader() {
        String csv = """
            #score_date:2026-04-29T00:00:00Z
            CVE-0001,0.1,0.2
            """;
        assertThatThrownBy(() -> EpssCsvParser.parse(new StringReader(csv)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("expected EPSS CSV header");
    }

    @Test
    void parse_defaultsScoreDateWhenCommentMissing() throws Exception {
        String csv = """
            cve,epss,percentile
            CVE-0001,0.1,0.2
            """;
        var result = EpssCsvParser.parse(new StringReader(csv));
        assertThat(result.scoreDate()).isNotNull();
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        assertThat(result.scoreDate()).isBetween(today.minusDays(1), today.plusDays(1));
    }
}

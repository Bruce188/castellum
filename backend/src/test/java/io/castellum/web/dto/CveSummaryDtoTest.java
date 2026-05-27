package io.castellum.web.dto;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the schema-of-the-wire for {@link CveSummaryDto} after the v3-F1 additions of
 * {@code kev}, {@code epssScore}, and {@code compositeScore}. These tests instantiate
 * the record via its positional constructor — if the constructor signature changes,
 * these tests break loudly.
 */
class CveSummaryDtoTest {

    private static final Instant PUBLISHED = Instant.parse("2023-11-07T03:18:00.640Z");
    private static final Instant LAST_MOD = Instant.parse("2024-01-01T00:00:00Z");
    private static final Instant FETCHED = Instant.parse("2024-02-01T00:00:00Z");

    @Test
    void kevTrueWithEpssAndCompositePopulated() {
        CveSummaryDto dto = new CveSummaryDto(
                "CVE-2024-0001",
                PUBLISHED,
                LAST_MOD,
                "Analyzed",
                "test description",
                new BigDecimal("8.0"),
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                null,
                null,
                null,
                null,
                FETCHED,
                Boolean.TRUE,
                new BigDecimal("0.0532"),
                new BigDecimal("8.50"));

        assertThat(dto.kev()).isTrue();
        assertThat(dto.epssScore()).isEqualByComparingTo("0.0532");
        assertThat(dto.compositeScore()).isEqualByComparingTo("8.50");
    }

    @Test
    void kevFalseWithNullEpssAndComposite() {
        CveSummaryDto dto = new CveSummaryDto(
                "CVE-2024-0002",
                PUBLISHED,
                LAST_MOD,
                "Analyzed",
                "test description",
                new BigDecimal("5.0"),
                "v3.1 vector",
                null,
                null,
                null,
                null,
                FETCHED,
                Boolean.FALSE,
                null,
                null);

        assertThat(dto.kev()).isFalse();
        assertThat(dto.epssScore()).isNull();
        assertThat(dto.compositeScore()).isNull();
    }

    @Test
    void kevTrueWithNullEpssOnlyComposite() {
        CveSummaryDto dto = new CveSummaryDto(
                "CVE-2024-0003",
                PUBLISHED,
                LAST_MOD,
                "Analyzed",
                "test description",
                new BigDecimal("3.1"),
                "v3.1 vector",
                null,
                null,
                null,
                null,
                FETCHED,
                Boolean.TRUE,
                null,
                new BigDecimal("3.10"));

        assertThat(dto.kev()).isTrue();
        assertThat(dto.epssScore()).isNull();
        assertThat(dto.compositeScore()).isEqualByComparingTo("3.10");
    }
}

package io.castellum;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

class FlywayIdempotencyTest {

    @Test
    void secondMigrateIsNoOp() {
        Flyway flyway = Flyway.configure()
            .dataSource(
                "jdbc:h2:mem:idempo;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa", "")
            .locations("classpath:db/migration/h2")
            .load();

        MigrateResult first = flyway.migrate();
        assertThat(first.migrationsExecuted)
            .as("first migrate must apply all H2-mirror migrations")
            .isGreaterThanOrEqualTo(10);

        MigrateResult second = flyway.migrate();
        assertThat(second.migrationsExecuted)
            .as("second migrate must be a no-op")
            .isZero();
        assertThat(flyway.info().pending())
            .as("no pending migrations after first migrate")
            .isEmpty();
    }

    /**
     * V21 regression — the {@code kev_entry.ingested_at} index must exist after migration.
     *
     * <p>{@code GET /api/risk/feeds/status} calls {@code KevEntryRepository.findMaxIngestedAt()},
     * a {@code MAX(ingested_at)} aggregate. V21 adds {@code kev_entry_ingested_at_idx} so that
     * aggregate is an index scan rather than a full-table scan. The default {@code @DataJpaTest}
     * profile disables Flyway and builds the schema from Hibernate DDL (no index), so this test
     * runs Flyway explicitly against H2 — the same mechanism as {@link #secondMigrateIsNoOp()} —
     * and asserts the index landed via {@link DatabaseMetaData#getIndexInfo} (version-agnostic;
     * does not depend on H2's {@code INFORMATION_SCHEMA} column naming).
     */
    @Test
    void v21_createsKevIngestedAtIndex() throws Exception {
        Flyway flyway = Flyway.configure()
            .dataSource(
                "jdbc:h2:mem:v21idx;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa", "")
            .locations("classpath:db/migration/h2")
            .load();
        flyway.migrate();

        DataSource ds = flyway.getConfiguration().getDataSource();
        boolean indexFound = false;
        try (Connection conn = ds.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            // H2 in PostgreSQL mode lower-cases unquoted identifiers; query both the
            // table name and column to confirm the index covers ingested_at.
            for (String tableName : new String[] {"kev_entry", "KEV_ENTRY"}) {
                try (ResultSet rs = meta.getIndexInfo(null, null, tableName, false, false)) {
                    while (rs.next()) {
                        String idxName = rs.getString("INDEX_NAME");
                        String colName = rs.getString("COLUMN_NAME");
                        if (idxName != null
                                && idxName.toLowerCase(Locale.ROOT).contains("ingested_at")
                                && colName != null
                                && colName.toLowerCase(Locale.ROOT).equals("ingested_at")) {
                            indexFound = true;
                        }
                    }
                }
                if (indexFound) break;
            }
        }

        assertThat(indexFound)
            .as("V21 must create an index on kev_entry(ingested_at) backing findMaxIngestedAt()")
            .isTrue();
    }
}

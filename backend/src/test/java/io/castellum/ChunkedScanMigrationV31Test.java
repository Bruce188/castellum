package io.castellum;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V31 — chunked wide-range scanning columns on {@code scan}.
 *
 * <p>The migration must add {@code skip_host_discovery BOOLEAN NOT NULL DEFAULT FALSE},
 * {@code chunks_total INT} and {@code chunks_done INT}, and backfill pre-existing rows
 * with {@code chunks_total = 1} and {@code chunks_done = 1 when status='COMPLETE' else 0}.
 *
 * <p>Same raw-Flyway-against-H2 mechanism as {@link FlywayIdempotencyTest}: the backfill
 * test migrates to V30 first, seeds legacy rows, then migrates to latest so the V31
 * backfill runs against genuinely pre-existing data.
 */
class ChunkedScanMigrationV31Test {

    @Test
    void v31_addsChunkColumnsToScanTable() throws Exception {
        Flyway flyway = Flyway.configure()
            .dataSource(
                "jdbc:h2:mem:v31cols;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa", "")
            .locations("classpath:db/migration/h2")
            .load();
        flyway.migrate();

        boolean skipColFound = false;
        boolean chunksTotalFound = false;
        boolean chunksDoneFound = false;
        DataSource ds = flyway.getConfiguration().getDataSource();
        try (Connection conn = ds.getConnection()) {
            DatabaseMetaData meta = conn.getMetaData();
            // H2 in PostgreSQL mode lower-cases unquoted identifiers; try both casings.
            for (String tableName : new String[] {"scan", "SCAN"}) {
                try (ResultSet rs = meta.getColumns(null, null, tableName, "%")) {
                    while (rs.next()) {
                        String col = rs.getString("COLUMN_NAME").toLowerCase(Locale.ROOT);
                        if (col.equals("skip_host_discovery")) skipColFound = true;
                        if (col.equals("chunks_total"))        chunksTotalFound = true;
                        if (col.equals("chunks_done"))         chunksDoneFound = true;
                    }
                }
                if (skipColFound && chunksTotalFound && chunksDoneFound) break;
            }
        }

        assertThat(skipColFound)
            .as("V31 must add skip_host_discovery column to scan table")
            .isTrue();
        assertThat(chunksTotalFound)
            .as("V31 must add chunks_total column to scan table")
            .isTrue();
        assertThat(chunksDoneFound)
            .as("V31 must add chunks_done column to scan table")
            .isTrue();
    }

    @Test
    void v31_backfillsLegacyRows_chunksTotalOne_chunksDoneByStatus() throws Exception {
        String url = "jdbc:h2:mem:v31backfill;MODE=PostgreSQL;DB_CLOSE_DELAY=-1";

        // 1. Migrate only as far as V30 — the world before this feature.
        Flyway toV30 = Flyway.configure()
            .dataSource(url, "sa", "")
            .locations("classpath:db/migration/h2")
            .target("30")
            .load();
        toV30.migrate();

        // 2. Seed legacy scan rows (no chunk columns exist yet).
        DataSource ds = toV30.getConfiguration().getDataSource();
        try (Connection conn = ds.getConnection(); Statement st = conn.createStatement()) {
            st.executeUpdate("INSERT INTO scan (cidr, scan_type, status, requested_at) "
                + "VALUES ('10.31.0.0/24', 'PING_SWEEP', 'COMPLETE', CURRENT_TIMESTAMP)");
            st.executeUpdate("INSERT INTO scan (cidr, scan_type, status, requested_at) "
                + "VALUES ('10.31.1.0/24', 'PING_SWEEP', 'FAILED', CURRENT_TIMESTAMP)");
            st.executeUpdate("INSERT INTO scan (cidr, scan_type, status, requested_at) "
                + "VALUES ('10.31.2.0/24', 'PING_SWEEP', 'PENDING', CURRENT_TIMESTAMP)");
        }

        // 3. Migrate to latest — V31 must apply and backfill the seeded rows.
        Flyway toLatest = Flyway.configure()
            .dataSource(url, "sa", "")
            .locations("classpath:db/migration/h2")
            .load();
        toLatest.migrate();

        try (Connection conn = ds.getConnection(); Statement st = conn.createStatement()) {
            try (ResultSet rs = st.executeQuery(
                    "SELECT status, skip_host_discovery, chunks_total, chunks_done "
                    + "FROM scan ORDER BY id")) {
                int rows = 0;
                while (rs.next()) {
                    rows++;
                    String status = rs.getString("status");
                    assertThat(rs.getBoolean("skip_host_discovery"))
                        .as("legacy rows must backfill skip_host_discovery = FALSE")
                        .isFalse();
                    assertThat(rs.getInt("chunks_total"))
                        .as("legacy rows must backfill chunks_total = 1")
                        .isEqualTo(1);
                    int expectedDone = "COMPLETE".equals(status) ? 1 : 0;
                    assertThat(rs.getInt("chunks_done"))
                        .as("legacy %s row must backfill chunks_done = %d", status, expectedDone)
                        .isEqualTo(expectedDone);
                }
                assertThat(rows).as("all three seeded rows must survive V31").isEqualTo(3);
            }
        }
    }
}

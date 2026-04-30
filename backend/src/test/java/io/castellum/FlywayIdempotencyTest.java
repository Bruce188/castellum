package io.castellum;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.Test;

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
}

package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the {@link RoleHint#rank(RoleHint)} total order — the single source of
 * truth for every merge / sticky-upgrade decision. The literal table
 * (not ordinal arithmetic) is the contract: reordering enum constants must not
 * silently reorder merge priority.
 */
class RoleHintTest {

    @Test
    void rank_nullIsZero_neverClears() {
        assertThat(RoleHint.rank(null))
            .as("incoming null is rank 0 — 'no evidence', never 'evidence of nothing'")
            .isEqualTo(0);
    }

    @Test
    void rank_totalOrderMatchesSpecTable() {
        assertThat(RoleHint.rank(RoleHint.GATEWAY)).isEqualTo(5);
        assertThat(RoleHint.rank(RoleHint.DHCP_SERVER)).isEqualTo(4);
        assertThat(RoleHint.rank(RoleHint.DNS_SERVER)).isEqualTo(3);
        assertThat(RoleHint.rank(RoleHint.LAPTOP_CHASSIS)).isEqualTo(2);
        assertThat(RoleHint.rank(RoleHint.DESKTOP_CHASSIS)).isEqualTo(1);
    }
}

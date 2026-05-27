package io.castellum.web;

import io.castellum.web.dto.InterfaceInfoDto;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the {@link InterfaceInfoDto} record shape.
 *
 * <p>Verifies that the 5-component record exposes {@code ipAddress()} and
 * {@code prefix()} accessors so AC5 is satisfied at the DTO layer.
 * Does NOT assert host-specific IP values — CI runners differ.
 */
class InterfaceInfoDtoTest {

    @Test
    void record_fiveComponents_accessorsReturnExpectedValues() {
        InterfaceInfoDto dto = new InterfaceInfoDto("eth6", "eth6", 1500, "192.168.68.51", 22);

        assertThat(dto.name()).isEqualTo("eth6");
        assertThat(dto.displayName()).isEqualTo("eth6");
        assertThat(dto.mtu()).isEqualTo(1500);
        assertThat(dto.ipAddress()).isEqualTo("192.168.68.51");
        assertThat(dto.prefix()).isEqualTo(22);
    }

    @Test
    void record_nullIpAddress_returnsNull() {
        InterfaceInfoDto dto = new InterfaceInfoDto("lo", "lo", 65536, null, 0);

        assertThat(dto.ipAddress()).isNull();
        assertThat(dto.prefix()).isEqualTo(0);
    }

    @Test
    void record_zeroPrefix_representsUnknown() {
        InterfaceInfoDto dto = new InterfaceInfoDto("eth0", "eth0", 1500, null, 0);

        assertThat(dto.prefix()).isZero();
    }
}

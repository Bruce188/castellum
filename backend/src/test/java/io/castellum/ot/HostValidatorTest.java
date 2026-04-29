package io.castellum.ot;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HostValidatorTest {

    // --- Valid addresses ---

    @Test
    void isValid_normalPrivateAddress_returnsTrue() {
        assertThat(HostValidator.isValid("192.168.1.100")).isTrue();
    }

    @Test
    void isValid_loopback_returnsTrue() {
        assertThat(HostValidator.isValid("127.0.0.1")).isTrue();
        assertThat(HostValidator.isValid("127.255.255.255")).isTrue();
    }

    @Test
    void isValid_linkLocal_returnsTrue() {
        assertThat(HostValidator.isValid("169.254.1.1")).isTrue();
    }

    @Test
    void isValid_publicAddress_returnsTrue() {
        assertThat(HostValidator.isValid("8.8.8.8")).isTrue();
    }

    // --- Rejected addresses ---

    @Test
    void isValid_hostname_returnsFalse() {
        assertThat(HostValidator.isValid("example.com")).isFalse();
        assertThat(HostValidator.isValid("localhost")).isFalse();
    }

    @Test
    void isValid_ipv6_returnsFalse() {
        assertThat(HostValidator.isValid("::1")).isFalse();
        assertThat(HostValidator.isValid("2001:db8::1")).isFalse();
    }

    @Test
    void isValid_allZeros_returnsFalse() {
        assertThat(HostValidator.isValid("0.0.0.0")).isFalse();
    }

    @Test
    void isValid_broadcast_returnsFalse() {
        assertThat(HostValidator.isValid("255.255.255.255")).isFalse();
    }

    @Test
    void isValid_multicastLow_returnsFalse() {
        assertThat(HostValidator.isValid("224.0.0.1")).isFalse();
    }

    @Test
    void isValid_multicastHigh_returnsFalse() {
        assertThat(HostValidator.isValid("239.255.255.255")).isFalse();
    }

    @Test
    void isValid_nullInput_returnsFalse() {
        assertThat(HostValidator.isValid(null)).isFalse();
    }

    @Test
    void isValid_emptyString_returnsFalse() {
        assertThat(HostValidator.isValid("")).isFalse();
    }

    @Test
    void isValid_outOfRangeOctet_returnsFalse() {
        assertThat(HostValidator.isValid("256.0.0.1")).isFalse();
        assertThat(HostValidator.isValid("192.168.1.999")).isFalse();
    }

    // --- requireValid ---

    @Test
    void requireValid_validAddress_returnsInetAddress() {
        InetAddress addr = HostValidator.requireValid("10.0.0.1");
        assertThat(addr.getHostAddress()).isEqualTo("10.0.0.1");
    }

    @Test
    void requireValid_loopback_returnsInetAddress() {
        InetAddress addr = HostValidator.requireValid("127.0.0.1");
        assertThat(addr.getHostAddress()).isEqualTo("127.0.0.1");
    }

    @Test
    void requireValid_hostname_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> HostValidator.requireValid("example.com"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requireValid_ipv6_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> HostValidator.requireValid("::1"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requireValid_multicast_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> HostValidator.requireValid("224.0.0.1"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requireValid_broadcast_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> HostValidator.requireValid("255.255.255.255"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requireValid_allZeros_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> HostValidator.requireValid("0.0.0.0"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requireValid_noDnsResolution_usesRawBytes() {
        // getByAddress(byte[]) is used — no DNS lookup possible
        InetAddress addr = HostValidator.requireValid("192.168.99.1");
        // InetAddress.getHostAddress() returns the dotted-quad without DNS lookup
        assertThat(addr.getHostAddress()).isEqualTo("192.168.99.1");
    }
}

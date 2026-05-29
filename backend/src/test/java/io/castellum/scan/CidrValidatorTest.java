package io.castellum.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CidrValidatorTest {

    @Test
    void validCidrs() {
        assertTrue(CidrValidator.isValid("192.168.1.0/24"));
        assertTrue(CidrValidator.isValid("10.0.0.0/8"));
        assertTrue(CidrValidator.isValid("172.16.0.0/16"));
        assertTrue(CidrValidator.isValid("192.168.0.0/22"));
    }

    @Test
    void invalidCidrs() {
        assertFalse(CidrValidator.isValid("not-a-cidr"));
        assertFalse(CidrValidator.isValid("; rm -rf /"));
        assertFalse(CidrValidator.isValid("192.168.1.0/24; ls"));
        assertFalse(CidrValidator.isValid(""));
        assertFalse(CidrValidator.isValid(null));
    }

    @Test
    void outOfRangeOctets_rejected() {
        assertFalse(CidrValidator.isValid("999.999.999.999/24"),
            "Out-of-range octets must be rejected");
        assertFalse(CidrValidator.isValid("256.0.0.0/24"),
            "Octet 256 must be rejected");
        assertFalse(CidrValidator.isValid("192.168.1.0/99"),
            "Prefix length 99 must be rejected");
    }

    @Test
    void broadRanges_rejectedByMinPrefixFloor() {
        assertFalse(CidrValidator.isValid("0.0.0.0/0"),
            "0.0.0.0/0 should be rejected — would scan the entire internet");
        assertFalse(CidrValidator.isValid("10.0.0.0/4"),
            "Prefix shorter than MIN_PREFIX_LENGTH must be rejected");
        assertFalse(CidrValidator.isValid("255.255.255.255/7"),
            "Prefix 7 is below minimum");
    }

    @Test
    void minimumPrefixBoundary_accepted() {
        assertTrue(CidrValidator.isValid("10.0.0.0/8"),
            "Exact minimum prefix length should be accepted");
    }

    @Test
    void requireValid_throwsForInvalidInput() {
        assertThrows(IllegalArgumentException.class, () -> CidrValidator.requireValid("not-a-cidr"));
        assertThrows(IllegalArgumentException.class, () -> CidrValidator.requireValid("0.0.0.0/0"));
        assertThrows(IllegalArgumentException.class, () -> CidrValidator.requireValid("999.999.999.999/24"));
    }

    @Test
    void requireValid_returnsInputForValidCidr() {
        String result = CidrValidator.requireValid("192.168.1.0/24");
        assertEquals("192.168.1.0/24", result);
    }

    // -----------------------------------------------------------------------
    // Host-address validation (alive-host target list)
    // -----------------------------------------------------------------------

    @Test
    void isValidHost_acceptsDottedQuad_rejectsCidrAndJunk() {
        assertTrue(CidrValidator.isValidHost("192.168.1.10"));
        assertTrue(CidrValidator.isValidHost("10.0.0.1"));
        assertFalse(CidrValidator.isValidHost("192.168.1.0/24"), "a CIDR is not a host");
        assertFalse(CidrValidator.isValidHost("256.0.0.1"), "out-of-range octet rejected");
        assertFalse(CidrValidator.isValidHost("; rm -rf /"));
        assertFalse(CidrValidator.isValidHost(""));
        assertFalse(CidrValidator.isValidHost(null));
    }

    @Test
    void requireValidHost_throwsForCidrOrJunk_returnsInputForHost() {
        assertEquals("10.1.2.3", CidrValidator.requireValidHost("10.1.2.3"));
        assertThrows(IllegalArgumentException.class, () -> CidrValidator.requireValidHost("10.0.0.0/24"));
        assertThrows(IllegalArgumentException.class, () -> CidrValidator.requireValidHost("not-an-ip"));
    }

    // -----------------------------------------------------------------------
    // IPv4 CIDR containment
    // -----------------------------------------------------------------------

    @Test
    void cidrContainsHost_withinAndOutside() {
        assertTrue(CidrValidator.cidrContainsHost("192.168.1.0/24", "192.168.1.10"));
        assertTrue(CidrValidator.cidrContainsHost("192.168.1.0/24", "192.168.1.255"));
        assertFalse(CidrValidator.cidrContainsHost("192.168.1.0/24", "192.168.2.1"),
            "host in adjacent /24 is outside");
    }

    @Test
    void cidrContainsHost_slash22_spansFourClassCBlocks() {
        // 192.168.0.0/22 covers 192.168.0.0 – 192.168.3.255 (the bug's /22 case).
        assertTrue(CidrValidator.cidrContainsHost("192.168.0.0/22", "192.168.0.1"));
        assertTrue(CidrValidator.cidrContainsHost("192.168.0.0/22", "192.168.3.254"));
        assertFalse(CidrValidator.cidrContainsHost("192.168.0.0/22", "192.168.4.1"),
            "192.168.4.1 is the first address beyond the /22");
    }

    @Test
    void cidrContainsHost_nullsAndMalformed_returnFalse() {
        assertFalse(CidrValidator.cidrContainsHost(null, "10.0.0.1"));
        assertFalse(CidrValidator.cidrContainsHost("10.0.0.0/24", null));
        assertFalse(CidrValidator.cidrContainsHost("not-a-cidr", "10.0.0.1"));
        assertFalse(CidrValidator.cidrContainsHost("10.0.0.0/24", "10.0.0.0/24"),
            "second arg must be a host, not a CIDR");
    }
}

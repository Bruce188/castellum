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
}

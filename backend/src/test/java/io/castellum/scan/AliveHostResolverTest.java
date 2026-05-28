package io.castellum.scan;

import io.castellum.domain.DeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Plain Mockito tests for {@link AliveHostResolver}. The repository is mocked so the
 * containment + dedup logic is exercised without a database.
 */
@ExtendWith(MockitoExtension.class)
class AliveHostResolverTest {

    @Mock DeviceRepository deviceRepository;

    AliveHostResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new AliveHostResolver(deviceRepository);
    }

    @Test
    void aliveHostsIn_filtersToHostsWithinCidr() {
        when(deviceRepository.findAllIpAddresses()).thenReturn(List.of(
            "192.168.1.5",   // in
            "192.168.1.9",   // in
            "192.168.2.1",   // out (adjacent /24)
            "10.0.0.1"));    // out
        List<String> alive = resolver.aliveHostsIn("192.168.1.0/24");
        assertEquals(List.of("192.168.1.5", "192.168.1.9"), alive);
    }

    @Test
    void aliveHostsIn_emptyInventory_returnsEmpty() {
        when(deviceRepository.findAllIpAddresses()).thenReturn(List.of());
        assertTrue(resolver.aliveHostsIn("192.168.1.0/24").isEmpty());
    }

    @Test
    void aliveHostsIn_noneWithinCidr_returnsEmpty() {
        when(deviceRepository.findAllIpAddresses()).thenReturn(List.of("10.0.0.1", "10.0.0.2"));
        assertTrue(resolver.aliveHostsIn("192.168.1.0/24").isEmpty(),
            "hosts outside the CIDR must not be returned (no whole-range fallback)");
    }

    @Test
    void aliveHostsIn_dedupesAndSkipsNullsAndMalformed() {
        when(deviceRepository.findAllIpAddresses()).thenReturn(Arrays.asList(
            "192.168.1.5",
            "192.168.1.5",    // duplicate
            null,             // null IP guarded
            "garbage",        // malformed → excluded by containment check
            "192.168.1.6"));
        List<String> alive = resolver.aliveHostsIn("192.168.1.0/24");
        assertEquals(List.of("192.168.1.5", "192.168.1.6"), alive);
    }

    @Test
    void aliveHostsIn_slash22_spansBlocks() {
        when(deviceRepository.findAllIpAddresses()).thenReturn(List.of(
            "192.168.0.10",   // in
            "192.168.3.250",  // in (still within /22)
            "192.168.4.1"));  // out (beyond /22)
        List<String> alive = resolver.aliveHostsIn("192.168.0.0/22");
        assertEquals(List.of("192.168.0.10", "192.168.3.250"), alive);
    }
}

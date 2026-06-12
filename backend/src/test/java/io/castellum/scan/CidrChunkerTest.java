package io.castellum.scan;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link CidrChunker#chunkInto(String, int)} — splits a wide CIDR into the
 * /chunkPrefix subnets covering the range, in ascending network order.
 *
 * <p>Inputs at or narrower than the chunk prefix come back as a singleton list,
 * unchanged. Host bits set on a wider input are normalized to the network
 * address before chunking. Invalid CIDRs throw IllegalArgumentException with
 * the same semantics as {@link CidrValidator}.
 */
class CidrChunkerTest {

    @Test
    void slash24_atOrNarrowerThanChunkPrefix_returnsSingletonUnchanged() {
        assertEquals(List.of("10.0.0.0/24"), CidrChunker.chunkInto("10.0.0.0/24", 22));
    }

    @Test
    void slash22_exactlyChunkPrefix_returnsSingletonUnchanged() {
        assertEquals(List.of("10.0.0.0/22"), CidrChunker.chunkInto("10.0.0.0/22", 22));
    }

    @Test
    void slash32_singleHost_returnsSingletonUnchanged() {
        assertEquals(List.of("192.168.1.5/32"), CidrChunker.chunkInto("192.168.1.5/32", 22));
    }

    @Test
    void slash20_returnsFourSlash22Chunks_ascendingNetworkOrder() {
        assertEquals(
            List.of("10.0.0.0/22", "10.0.4.0/22", "10.0.8.0/22", "10.0.12.0/22"),
            CidrChunker.chunkInto("10.0.0.0/20", 22));
    }

    @Test
    void slash16_returns64Chunks_firstAndLastPinned() {
        List<String> chunks = CidrChunker.chunkInto("10.0.0.0/16", 22);
        assertEquals(64, chunks.size(), "a /16 covers 64 /22 subnets");
        assertEquals("10.0.0.0/22", chunks.get(0));
        assertEquals("10.0.252.0/22", chunks.get(63));
        // Full ascending coverage: chunk i starts at third-octet i*4.
        for (int i = 0; i < 64; i++) {
            assertEquals("10.0." + (i * 4) + ".0/22", chunks.get(i),
                "chunk " + i + " must be the i-th /22 in ascending network order");
        }
    }

    @Test
    void hostBitsSet_normalizedToNetworkAddressBeforeChunking() {
        assertEquals(
            CidrChunker.chunkInto("10.0.0.0/20", 22),
            CidrChunker.chunkInto("10.0.1.5/20", 22),
            "10.0.1.5/20 must chunk identically to 10.0.0.0/20");
    }

    @Test
    void invalidCidr_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> CidrChunker.chunkInto("not-a-cidr", 22));
        assertThrows(IllegalArgumentException.class, () -> CidrChunker.chunkInto("300.0.0.0/16", 22));
        assertThrows(IllegalArgumentException.class, () -> CidrChunker.chunkInto("10.0.0.0/7", 22),
            "prefixes shorter than /8 are invalid per CidrValidator");
        assertThrows(IllegalArgumentException.class, () -> CidrChunker.chunkInto(null, 22));
    }
}

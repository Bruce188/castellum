package io.castellum.scan;

import java.util.ArrayList;
import java.util.List;

/**
 * Splits a wide CIDR into the /chunkPrefix subnets covering its range, in
 * ascending network order, so the scan engine can execute one bounded nmap
 * run per chunk instead of handing the whole range to a single process.
 *
 * <p>Inputs at or narrower than the chunk prefix come back as a singleton list,
 * unchanged. Host bits set on a wider input are normalized to the network
 * address before chunking. Invalid CIDRs throw {@link IllegalArgumentException}
 * with the same semantics as {@link CidrValidator}.
 */
public final class CidrChunker {

    private CidrChunker() {}

    /**
     * Chunk {@code cidr} into the ascending list of /{@code chunkPrefix} subnets
     * covering its (network-address-normalized) range.
     *
     * @param cidr        a CIDR that satisfies {@link CidrValidator#isValid(String)}
     * @param chunkPrefix the prefix length of each chunk (e.g. 22)
     * @return the input unchanged as a singleton list when its prefix is already
     *         {@code >= chunkPrefix}; otherwise the covering /chunkPrefix subnets
     * @throws IllegalArgumentException for null or invalid CIDRs
     */
    public static List<String> chunkInto(String cidr, int chunkPrefix) {
        CidrValidator.requireValid(cidr);

        int slash = cidr.lastIndexOf('/');
        int prefix = Integer.parseInt(cidr.substring(slash + 1));
        if (prefix >= chunkPrefix) {
            return List.of(cidr);
        }

        Integer addr = CidrValidator.toInt(cidr.substring(0, slash));
        if (addr == null) {
            throw new IllegalArgumentException("invalid CIDR");
        }
        // Normalize to the network address: drop any host bits the caller set.
        int network = CidrValidator.networkOf(addr, prefix);

        int chunkCount = 1 << (chunkPrefix - prefix);
        int chunkSize = 1 << (32 - chunkPrefix);
        List<String> chunks = new ArrayList<>(chunkCount);
        for (int i = 0; i < chunkCount; i++) {
            chunks.add(CidrValidator.toDottedQuad(network + i * chunkSize) + "/" + chunkPrefix);
        }
        return chunks;
    }
}

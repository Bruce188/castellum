package io.castellum.ot.s7;

import io.castellum.ot.OtProbeDecodeException;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure-function parser for S7comm SZL 0x0011 (Module Identification) responses.
 *
 * <p>Decodes the manufacturer, ordering number, and firmware version from the
 * SZL payload bytes returned by S7Probe.
 */
public final class S7Decoder {

    /** Maximum SZL records per spec; bounded by negotiated PDU length (~960 bytes typical). */
    static final int MAX_SZL_RECORDS = 16;

    /** Expected SZL ID for module identification. */
    private static final int EXPECTED_SZL_ID = 0x0011;

    private S7Decoder() {}

    /**
     * Decodes an SZL 0x0011 (Module Identification) response.
     *
     * <p>The input is the raw S7 SZL response payload after TPKT/COTP stripping.
     * Expected structure:
     * <ul>
     *   <li>S7 header (10 bytes starting with 0x32)</li>
     *   <li>SZL return-value header (various)</li>
     *   <li>SZL data: length(2) + count(2) + records[count × 28 bytes each]</li>
     * </ul>
     *
     * @param szlResponse raw SZL response bytes (after TPKT/COTP header)
     * @return map with keys: manufacturer, ordering-number, firmware-version
     * @throws OtProbeDecodeException on bounds violation or unexpected SZL ID
     */
    public static Map<String, String> decode(byte[] szlResponse) {
        if (szlResponse == null || szlResponse.length < 14) {
            throw new OtProbeDecodeException(
                "S7: SZL response too short (length=" + (szlResponse == null ? 0 : szlResponse.length) + ")");
        }

        // Check S7 protocol ID (first byte after COTP DT header)
        // The input here is the full COTP payload: COTP-DT(3) + S7-payload
        // Offset 0=COTP-length, 1=DT, 2=tpdu-nr; S7 starts at offset 3
        int s7Start = 3;
        if (szlResponse.length < s7Start + 10) {
            throw new OtProbeDecodeException("S7: response too short for S7 header");
        }

        if ((szlResponse[s7Start] & 0xFF) != 0x32) {
            throw new OtProbeDecodeException(
                "S7: unexpected protocol byte 0x" + Integer.toHexString(szlResponse[s7Start] & 0xFF));
        }

        // S7 header at s7Start:
        // [0]=0x32 [1]=type [2-3]=reserved [4-5]=pdu-ref [6-7]=param-len [8-9]=data-len
        int paramLen = ((szlResponse[s7Start + 6] & 0xFF) << 8) | (szlResponse[s7Start + 7] & 0xFF);
        int dataLen = ((szlResponse[s7Start + 8] & 0xFF) << 8) | (szlResponse[s7Start + 9] & 0xFF);

        int dataStart = s7Start + 10 + paramLen;
        if (dataStart + dataLen > szlResponse.length) {
            throw new OtProbeDecodeException(
                "S7: data region overflows buffer (dataStart=" + dataStart + " dataLen=" + dataLen + ")");
        }

        // SZL data: starts at dataStart
        // Format: return-code(1) + transport-size(1) + szl-data-length(2) + szl-id(2) + szl-index(2) + szl-list-len(2) + szl-list-count(2) + records
        if (dataLen < 8) {
            throw new OtProbeDecodeException("S7: SZL data too short for header: " + dataLen);
        }

        int szlDataOffset = dataStart;
        // return-code at szlDataOffset[0], transport-size at [1], length(BE16) at [2-3]
        int szlId = ((szlResponse[szlDataOffset + 4] & 0xFF) << 8) | (szlResponse[szlDataOffset + 5] & 0xFF);
        if (szlId != EXPECTED_SZL_ID && szlId != 0x0000) {
            // Allow 0x0000 as "generic response" from some PLCs
            throw new OtProbeDecodeException(
                "S7: unexpected SZL ID 0x" + Integer.toHexString(szlId) + " (expected 0x0011)");
        }

        int szlListLen = ((szlResponse[szlDataOffset + 8] & 0xFF) << 8) | (szlResponse[szlDataOffset + 9] & 0xFF);
        int szlListCount = ((szlResponse[szlDataOffset + 10] & 0xFF) << 8) | (szlResponse[szlDataOffset + 11] & 0xFF);

        if (szlListCount > MAX_SZL_RECORDS) {
            throw new OtProbeDecodeException(
                "S7: SZL record count " + szlListCount + " exceeds maximum " + MAX_SZL_RECORDS);
        }

        int recordStart = szlDataOffset + 12;
        Map<String, String> result = new LinkedHashMap<>();

        if (szlListLen >= 28 && szlListCount >= 1 && recordStart + 28 <= szlResponse.length) {
            // First SZL 0x0011 record: index(2) + manufacturer(2) + reserved + order-number(20) + firmware(4)
            // index at recordStart[0-1], mlfb/order-number at [2-21] (20 bytes), firmware at [22-27] (6 bytes)
            int manufacturerCode = ((szlResponse[recordStart] & 0xFF) << 8) | (szlResponse[recordStart + 1] & 0xFF);
            result.put("manufacturer", resolveManufacturer(manufacturerCode));

            if (recordStart + 22 <= szlResponse.length) {
                // Order number: 20 bytes ASCII at offset +2
                int orderLen = Math.min(20, szlResponse.length - (recordStart + 2));
                String orderNum = new String(szlResponse, recordStart + 2, orderLen, StandardCharsets.US_ASCII).trim();
                if (!orderNum.isEmpty()) {
                    result.put("ordering-number", orderNum);
                }
            }

            if (recordStart + 28 <= szlResponse.length) {
                // Firmware: 4 bytes at offset +24 as version string
                String fw = new String(szlResponse, recordStart + 24, 4, StandardCharsets.US_ASCII).trim();
                if (!fw.isEmpty()) {
                    result.put("firmware-version", fw);
                }
            }
        } else {
            // Short or no records — just return what we can
            result.put("manufacturer", "Siemens");
        }

        return result;
    }

    private static String resolveManufacturer(int code) {
        // Siemens manufacturer code = 0x002A
        return switch (code) {
            case 0x002A, 0x0042 -> "Siemens";
            default -> "0x" + Integer.toHexString(code);
        };
    }
}

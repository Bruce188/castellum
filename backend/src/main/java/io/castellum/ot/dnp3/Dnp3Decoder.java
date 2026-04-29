package io.castellum.ot.dnp3;

import io.castellum.ot.OtProbeDecodeException;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure-function parser for DNP3 g0v254 (All Device Attributes) responses.
 *
 * <p>Validates per-block CRC and application function code before extracting attributes.
 * All length fields are validated against remaining buffer before access.
 *
 * <p><b>Frame structure:</b> data-link header (8 bytes) + DL CRC (2 bytes), followed by
 * user-data blocks each of up to 16 data bytes + 2 CRC bytes. CRC bytes are stripped before
 * parsing the application layer.
 *
 * <p><b>Beta status:</b> tested against synthetic canned fixtures only; not validated
 * against hardware DNP3 RTU.
 */
public final class Dnp3Decoder {

    /** Max attributes per response. Defensive bound against malformed responses. */
    static final int MAX_ATTRIBUTES = 64;

    /** Application function code: RESPONSE (0x81). */
    private static final int AL_FN_RESPONSE = 0x81;

    private Dnp3Decoder() {}

    /**
     * Decodes a DNP3 g0v254 (All Device Attributes) response frame.
     *
     * @param response raw received bytes (complete DNP3 TCP frame including all CRC fields)
     * @return map of attribute name → value (e.g. "device-name" → "Castellum-RTU")
     * @throws OtProbeDecodeException on CRC mismatch, bounds violation, or unsupported function code
     */
    public static Map<String, String> decode(byte[] response) {
        if (response == null || response.length < 12) {
            throw new OtProbeDecodeException(
                "DNP3: truncated frame (length=" + (response == null ? 0 : response.length) + ", min 12)");
        }

        // --- Step 1: validate data-link header CRC (bytes 0-7, CRC stored little-endian at 8-9) ---
        int headerCrc = Dnp3Crc.crc(response, 0, 8);
        int frameDlCrc = (response[9] & 0xFF) << 8 | (response[8] & 0xFF);
        if (headerCrc != frameDlCrc) {
            throw new OtProbeDecodeException(
                "DNP3: data-link header CRC mismatch (computed=0x" +
                Integer.toHexString(headerCrc) + ", frame=0x" + Integer.toHexString(frameDlCrc) + ")");
        }

        // --- Step 2: reassemble user data by stripping per-block CRCs ---
        // User data starts at offset 10. Each block = up to 16 data bytes + 2 CRC bytes.
        ByteArrayOutputStream userData = new ByteArrayOutputStream();
        int framePos = 10;
        while (framePos < response.length) {
            // How many data bytes remain in this block?
            int remaining = response.length - framePos;
            if (remaining <= 2) break; // only CRC bytes left — stop
            int blockDataLen = Math.min(16, remaining - 2);
            // Validate this block's CRC
            int blockCrc = Dnp3Crc.crc(response, framePos, blockDataLen);
            int storedCrc = (response[framePos + blockDataLen + 1] & 0xFF) << 8
                          | (response[framePos + blockDataLen] & 0xFF);
            if (blockCrc != storedCrc) {
                throw new OtProbeDecodeException(
                    "DNP3: data block CRC mismatch at frame offset " + framePos +
                    " (computed=0x" + Integer.toHexString(blockCrc) +
                    ", frame=0x" + Integer.toHexString(storedCrc) + ")");
            }
            userData.write(response, framePos, blockDataLen);
            framePos += blockDataLen + 2;
        }

        byte[] data = userData.toByteArray();
        // data layout: transport(0) + appCtrl(1) + appFn(2) + IIN1(3) + IIN2(4) + objects(5+)
        if (data.length < 3) {
            throw new OtProbeDecodeException("DNP3: truncated frame (no app layer data)");
        }

        // --- Step 3: validate application function code ---
        int appFn = data[2] & 0xFF;
        if (appFn != AL_FN_RESPONSE) {
            throw new OtProbeDecodeException(
                "DNP3: unexpected application function code 0x" + Integer.toHexString(appFn) +
                " (expected RESPONSE 0x81)");
        }

        // --- Step 4: skip IIN bytes, parse object headers ---
        // Minimum: transport(0) + appCtrl(1) + fn(2) + IIN1(3) + IIN2(4) = 5 bytes before objects
        int cursor = 5;
        Map<String, String> result = new LinkedHashMap<>();
        int attrCount = 0;

        while (cursor < data.length && attrCount < MAX_ATTRIBUTES) {
            if (cursor + 3 >= data.length) break; // need at least group+var+qual+len

            int group = data[cursor] & 0xFF;
            int variation = data[cursor + 1] & 0xFF;
            int qualifier = data[cursor + 2] & 0xFF;

            if (group == 0 && qualifier == 0x00) {
                // g0vX attribute: qualifier 0x00 = count-of-objects (1 byte count follows)
                if (cursor + 4 > data.length) break;
                int attrLen = data[cursor + 3] & 0xFF;
                if (cursor + 4 + attrLen > data.length) {
                    throw new OtProbeDecodeException(
                        "DNP3: attribute length overrun at data cursor=" + cursor);
                }
                String value = new String(data, cursor + 4, attrLen, StandardCharsets.US_ASCII);
                result.put(attributeName(variation), value);
                cursor += 4 + attrLen;
                attrCount++;
            } else {
                // Unknown object type — stop parsing
                break;
            }
        }

        return result;
    }

    private static String attributeName(int variation) {
        return switch (variation) {
            case 196 -> "device-name";
            case 243 -> "vendor-name";
            case 244 -> "device-description";
            case 245 -> "device-serial-number";
            default -> "attr-0-" + variation;
        };
    }
}

package io.castellum.ot.bacnet;

import io.castellum.ot.OtProbeDecodeException;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure-function parser for BACnet/IP I-Am and ReadProperty-Ack responses.
 *
 * <p>All length fields validated against remaining buffer before access.
 */
public final class BacnetDecoder {

    static final int MAX_PROPERTIES = 100;

    private BacnetDecoder() {}

    /**
     * Decoded result of a BACnet I-Am response.
     *
     * @param deviceId     BACnet device instance number
     * @param vendorId     ASHRAE vendor id
     * @param maxApdu      maximum APDU length accepted
     * @param segmentation segmentation capability code
     */
    public record IAm(long deviceId, int vendorId, int maxApdu, int segmentation) {}

    /**
     * Decodes a BACnet I-Am unconfirmed response.
     *
     * @param response full BVLL frame bytes
     * @return IAm record
     * @throws OtProbeDecodeException on validation failure
     */
    public static IAm decodeIAm(byte[] response) {
        validateBvll(response, "I-Am");

        // NPDU starts at offset 4; APDU after NPDU
        int npduStart = 4;
        if (response.length < npduStart + 2) {
            throw new OtProbeDecodeException("BACnet I-Am: truncated NPDU");
        }
        // NPDU control byte at [5]; if high bit set, more NPDU bytes follow (routing)
        int npduLen = 2; // minimal NPDU: version(1) + control(1)
        int npduControl = response[npduStart + 1] & 0xFF;
        // If destination present (bit 5), skip 3+1+hopcount bytes
        if ((npduControl & 0x20) != 0) npduLen += 3 + 1 + 1;
        // If source present (bit 3), skip 3+1 bytes
        if ((npduControl & 0x08) != 0) npduLen += 3 + 1;

        int apduStart = npduStart + npduLen;
        if (response.length < apduStart + 2) {
            throw new OtProbeDecodeException("BACnet I-Am: truncated APDU");
        }

        // APDU type byte 0: bits 7-4 = type (0001 = Unconfirmed), bits 3-0 = 0
        int apduType = (response[apduStart] >> 4) & 0x0F;
        if (apduType != 0x01) {
            throw new OtProbeDecodeException(
                "BACnet I-Am: expected unconfirmed APDU type (0x1x), got 0x" +
                Integer.toHexString(response[apduStart] & 0xFF));
        }

        // byte 1 = service choice (0x00 = I-Am)
        int svcChoice = response[apduStart + 1] & 0xFF;
        if (svcChoice != 0x00) {
            throw new OtProbeDecodeException(
                "BACnet I-Am: expected I-Am service (0x00), got 0x" + Integer.toHexString(svcChoice));
        }

        // I-Am parameters: objectIdentifier(4/context?), maxApdu, segmentation, vendorId
        // Encoded as BACnet application-tagged values
        int cursor = apduStart + 2;

        // objectIdentifier: context or app tag 0x0C (object-id, length 4)
        // If tag byte = 0x0C, app-tag 1 = object-id (type=2 = object-id, len=4)
        if (cursor >= response.length) {
            throw new OtProbeDecodeException("BACnet I-Am: missing object-id parameter");
        }

        // Application tag: tag number(4 bits) + class(1) + length(3 bits)
        // For object-id: tag=12 (0x0C = 1100 in 4 bits), class=0 (app), len=4
        // Tag byte = (12 << 4) | 0 | 4 = 0xC4
        int tagByte = response[cursor] & 0xFF;
        cursor++;
        int objIdLen = tagByte & 0x07;
        if (cursor + objIdLen > response.length) {
            throw new OtProbeDecodeException("BACnet I-Am: object-id overflows buffer");
        }
        long rawObjId = 0;
        for (int i = 0; i < objIdLen && i < 4; i++) {
            rawObjId = (rawObjId << 8) | (response[cursor + i] & 0xFF);
        }
        long deviceId = rawObjId & 0x3FFFFFL; // lower 22 bits = instance
        cursor += objIdLen;

        // maxApdu: unsigned int
        if (cursor >= response.length) {
            throw new OtProbeDecodeException("BACnet I-Am: missing maxApdu parameter");
        }
        int maxApduTagByte = response[cursor] & 0xFF;
        cursor++;
        int maxApduLen = maxApduTagByte & 0x07;
        if (cursor + maxApduLen > response.length) {
            throw new OtProbeDecodeException("BACnet I-Am: maxApdu overflows buffer");
        }
        int maxApdu = 0;
        for (int i = 0; i < maxApduLen && i < 4; i++) {
            maxApdu = (maxApdu << 8) | (response[cursor + i] & 0xFF);
        }
        cursor += maxApduLen;

        // segmentation: enumerated
        if (cursor >= response.length) {
            throw new OtProbeDecodeException("BACnet I-Am: missing segmentation parameter");
        }
        int segTagByte = response[cursor] & 0xFF;
        cursor++;
        int segLen = segTagByte & 0x07;
        int segmentation = 0;
        if (cursor + segLen <= response.length && segLen > 0) {
            segmentation = response[cursor] & 0xFF;
        }
        cursor += segLen;

        // vendorId: unsigned
        if (cursor >= response.length) {
            return new IAm(deviceId, 0, maxApdu, segmentation);
        }
        int vidTagByte = response[cursor] & 0xFF;
        cursor++;
        int vidLen = vidTagByte & 0x07;
        int vendorId = 0;
        for (int i = 0; i < vidLen && cursor + i < response.length; i++) {
            vendorId = (vendorId << 8) | (response[cursor + i] & 0xFF);
        }

        return new IAm(deviceId, vendorId, maxApdu, segmentation);
    }

    /**
     * Decodes a BACnet ReadProperty-Ack response into a property name → value map.
     *
     * @param response full BVLL frame bytes
     * @return map of property name → decoded string value
     * @throws OtProbeDecodeException on validation failure
     */
    public static Map<String, String> decodeReadPropertyAck(byte[] response) {
        validateBvll(response, "ReadPropertyAck");

        // Skip NPDU (minimal 2 bytes)
        int apduStart = 6;
        if (response.length < apduStart + 3) {
            throw new OtProbeDecodeException("BACnet ReadPropertyAck: truncated APDU");
        }

        // APDU: type=0x30 (Confirmed-ACK), invoke-id, service=0x0C (ReadProperty)
        int apduType = (response[apduStart] >> 4) & 0x0F;
        if (apduType != 0x03) {
            throw new OtProbeDecodeException(
                "BACnet ReadPropertyAck: expected Confirmed-ACK (0x3x), got 0x" +
                Integer.toHexString(response[apduStart] & 0xFF));
        }

        int svcChoice = response[apduStart + 2] & 0xFF;
        if (svcChoice != (BacnetFrames.SVC_READ_PROPERTY & 0xFF)) {
            throw new OtProbeDecodeException(
                "BACnet ReadPropertyAck: expected ReadProperty service (0x0C), got 0x" +
                Integer.toHexString(svcChoice));
        }

        // Parse property values from offset apduStart+3
        int cursor = apduStart + 3;
        Map<String, String> result = new LinkedHashMap<>();
        int propCount = 0;

        while (cursor < response.length && propCount < MAX_PROPERTIES) {
            int tagByte = response[cursor] & 0xFF;
            cursor++;
            // BACnet tag length/flag field: bits 2-0
            // 6 = opening tag, 7 = closing tag — both are structural, carry no value data
            int lf = tagByte & 0x07;
            if (lf == 6 || lf == 7) continue; // opening / closing tag, skip

            int len = lf;
            if (len == 5) {
                // Extended length: next byte holds the actual length
                if (cursor >= response.length) break;
                len = response[cursor] & 0xFF;
                cursor++;
            }
            if (len == 0) continue;
            if (cursor + len > response.length) {
                // Malformed — stop parsing rather than throwing so partial data is returned
                break;
            }
            String value = new String(response, cursor, len, StandardCharsets.UTF_8).trim();
            if (!value.isEmpty()) {
                String propName = "property-" + propCount;
                result.put(propName, value);
                propCount++;
            }
            cursor += len;
        }

        return result;
    }

    private static void validateBvll(byte[] response, String context) {
        if (response == null || response.length < 6) {
            throw new OtProbeDecodeException(
                "BACnet " + context + ": truncated frame (length=" +
                (response == null ? 0 : response.length) + ")");
        }
        if ((response[0] & 0xFF) != (BacnetFrames.BVLL_TYPE_BIP & 0xFF)) {
            throw new OtProbeDecodeException(
                "BACnet " + context + ": invalid BVLL type byte 0x" +
                Integer.toHexString(response[0] & 0xFF));
        }
        int bvllLen = ((response[2] & 0xFF) << 8) | (response[3] & 0xFF);
        if (bvllLen > response.length) {
            throw new OtProbeDecodeException(
                "BACnet " + context + ": BVLL length=" + bvllLen +
                " exceeds buffer length=" + response.length);
        }
    }
}

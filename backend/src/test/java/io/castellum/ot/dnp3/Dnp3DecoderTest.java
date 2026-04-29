package io.castellum.ot.dnp3;

import io.castellum.ot.OtProbeDecodeException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Dnp3DecoderTest {

    /** Loads the synthetic DNP3 g0v254 fixture from test resources. */
    private static byte[] loadFixture(String name) throws IOException {
        try (InputStream is = Dnp3DecoderTest.class.getResourceAsStream("/ot/" + name)) {
            if (is == null) throw new IOException("Resource not found: /ot/" + name);
            return is.readAllBytes();
        }
    }

    /**
     * Builds a minimal valid DNP3 frame with one g0v196 attribute (device-name).
     * Uses the same CRC algorithm as the production implementation.
     */
    private static byte[] buildSimpleFrame(String deviceName) {
        byte[] nameBuf = deviceName.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        // app layer: transport + appCtrl + RESPONSE + IIN(2) + attr(group=0, var=196, qual=0, len, data)
        byte[] appLayer = new byte[5 + 4 + nameBuf.length];
        appLayer[0] = (byte) 0xC0; // transport
        appLayer[1] = (byte) 0xC1; // app ctrl
        appLayer[2] = (byte) 0x81; // RESPONSE
        appLayer[3] = 0x00;        // IIN1
        appLayer[4] = 0x00;        // IIN2
        appLayer[5] = 0x00;        // group 0
        appLayer[6] = (byte) 196;  // variation 196 = device-name
        appLayer[7] = 0x00;        // qualifier
        appLayer[8] = (byte) nameBuf.length;
        System.arraycopy(nameBuf, 0, appLayer, 9, nameBuf.length);

        // Break into 16-byte blocks with CRCs appended
        byte[] blocked = blockWithCrc(appLayer);

        // DL header
        int dlLength = 5 + appLayer.length;
        byte[] dlHeader = {0x05, 0x64, (byte) dlLength, 0x44, 0x01, 0x00, 0x00, 0x04};
        byte[] frame = new byte[dlHeader.length + 2 + blocked.length];
        System.arraycopy(dlHeader, 0, frame, 0, 8);
        int dlCrc = Dnp3Crc.crc(dlHeader, 0, 8);
        frame[8] = (byte) (dlCrc & 0xFF);
        frame[9] = (byte) ((dlCrc >> 8) & 0xFF);
        System.arraycopy(blocked, 0, frame, 10, blocked.length);
        return frame;
    }

    /** Appends per-16-byte-block CRCs. */
    private static byte[] blockWithCrc(byte[] data) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int offset = 0;
        while (offset < data.length) {
            int len = Math.min(16, data.length - offset);
            int crc = Dnp3Crc.crc(data, offset, len);
            out.write(data, offset, len);
            out.write(crc & 0xFF);
            out.write((crc >> 8) & 0xFF);
            offset += len;
        }
        return out.toByteArray();
    }

    @Test
    void decode_canonicalG0v254Response_returnsAttributeMap() throws Exception {
        byte[] fixture = loadFixture("dnp3-g0v254-sample.bin");
        Map<String, String> result = Dnp3Decoder.decode(fixture);
        // Fixture contains device-name = "Castellum-Test-RTU"
        assertThat(result).containsKey("device-name");
        assertThat(result.get("device-name")).isEqualTo("Castellum-Test-RTU");
    }

    @Test
    void decode_inlineCanonicalResponse_returnsExpectedName() {
        byte[] frame = buildSimpleFrame("TestDevice");
        Map<String, String> result = Dnp3Decoder.decode(frame);
        assertThat(result).containsEntry("device-name", "TestDevice");
    }

    @Test
    void decode_crcMismatch_throwsOtProbeDecodeException() {
        byte[] frame = buildSimpleFrame("TestDevice");
        // Corrupt the DL header CRC byte 8
        frame[8] = (byte) (frame[8] ^ 0xFF);
        assertThatThrownBy(() -> Dnp3Decoder.decode(frame))
            .isInstanceOf(OtProbeDecodeException.class)
            .hasMessageContaining("CRC");
    }

    @Test
    void decode_truncatedFragment_throwsOtProbeDecodeException() {
        byte[] truncated = new byte[]{0x05, 0x64, 0x0A, 0x44, 0x01, 0x00};
        assertThatThrownBy(() -> Dnp3Decoder.decode(truncated))
            .isInstanceOf(OtProbeDecodeException.class);
    }

    @Test
    void decode_unexpectedFunctionCode_throwsOtProbeDecodeException() {
        byte[] frame = buildSimpleFrame("TestDevice");
        // Application function code is at offset 12
        frame[12] = 0x09; // WRITE (forbidden)
        // Recalculate the data block CRC so it passes CRC check but fails fn check
        // The data block starts at offset 10; recalc its CRC
        int newBlockCrc = Dnp3Crc.crc(frame, 10, Math.min(16, frame.length - 12));
        int blockCrcOffset = 10 + Math.min(16, frame.length - 12);
        if (blockCrcOffset + 1 < frame.length) {
            frame[blockCrcOffset] = (byte) (newBlockCrc & 0xFF);
            frame[blockCrcOffset + 1] = (byte) ((newBlockCrc >> 8) & 0xFF);
        }
        assertThatThrownBy(() -> Dnp3Decoder.decode(frame))
            .isInstanceOf(OtProbeDecodeException.class);
    }
}

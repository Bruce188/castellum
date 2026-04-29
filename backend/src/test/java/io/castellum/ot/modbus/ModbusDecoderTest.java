package io.castellum.ot.modbus;

import io.castellum.ot.OtProbeDecodeException;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ModbusDecoderTest {

    /** Builds a valid 3-object Read-Device-Identification response. */
    private static byte[] buildCanonicalResponse(String vendor, String productCode, String revision) {
        byte[] vb = vendor.getBytes();
        byte[] pb = productCode.getBytes();
        byte[] rb = revision.getBytes();

        int pduLen = 6 + 2 + vb.length + 2 + pb.length + 2 + rb.length;
        int mbapLength = 1 + pduLen;
        byte[] frame = new byte[7 + pduLen];
        frame[0] = 0x00; frame[1] = 0x01;
        frame[2] = 0x00; frame[3] = 0x00;
        frame[4] = (byte) ((mbapLength >> 8) & 0xFF);
        frame[5] = (byte) (mbapLength & 0xFF);
        frame[6] = 0x01;
        int i = 7;
        frame[i++] = 0x2B;
        frame[i++] = 0x0E;
        frame[i++] = 0x01;
        frame[i++] = 0x00;
        frame[i++] = 0x00;
        frame[i++] = 0x03;
        frame[i++] = 0x00; frame[i++] = (byte) vb.length;
        System.arraycopy(vb, 0, frame, i, vb.length); i += vb.length;
        frame[i++] = 0x01; frame[i++] = (byte) pb.length;
        System.arraycopy(pb, 0, frame, i, pb.length); i += pb.length;
        frame[i++] = 0x02; frame[i++] = (byte) rb.length;
        System.arraycopy(rb, 0, frame, i, rb.length);
        return frame;
    }

    @Test
    void decode_canonicalResponse_returnsExpectedMap() {
        byte[] frame = buildCanonicalResponse("Castellum-Test", "MOCK-1", "1.0");
        Map<Integer, String> result = ModbusDecoder.decode(frame);
        assertThat(result).containsEntry(0, "Castellum-Test");
        assertThat(result).containsEntry(1, "MOCK-1");
        assertThat(result).containsEntry(2, "1.0");
    }

    @Test
    void decode_truncatedFrame_throwsOtProbeDecodeException() {
        byte[] truncated = {0x00, 0x01, 0x00, 0x00}; // only 4 bytes
        assertThatThrownBy(() -> ModbusDecoder.decode(truncated))
            .isInstanceOf(OtProbeDecodeException.class);
    }

    @Test
    void decode_modbusExceptionResponse_throwsOtProbeDecodeException() {
        // FC 0xAB = exception response
        byte[] frame = new byte[9];
        frame[4] = 0x00; frame[5] = 0x03;
        frame[6] = 0x01;
        frame[7] = (byte) 0xAB; // exception function code
        frame[8] = 0x03;        // exception code
        assertThatThrownBy(() -> ModbusDecoder.decode(frame))
            .isInstanceOf(OtProbeDecodeException.class)
            .hasMessageContaining("modbus exception response");
    }

    @Test
    void decode_unexpectedFunctionCode_throwsOtProbeDecodeException() {
        // FC 0x10 = write multiple registers echo
        byte[] frame = new byte[9];
        frame[4] = 0x00; frame[5] = 0x03;
        frame[6] = 0x01;
        frame[7] = 0x10; // write multiple registers
        frame[8] = 0x00;
        assertThatThrownBy(() -> ModbusDecoder.decode(frame))
            .isInstanceOf(OtProbeDecodeException.class)
            .hasMessageContaining("unexpected function code");
    }

    @Test
    void decode_oversizedNumObjects_throwsOtProbeDecodeException() {
        // 8 objects = exceeds MAX_OBJECTS (7)
        byte[] frame = new byte[13];
        frame[4] = 0x00; frame[5] = 0x07;
        frame[6] = 0x01;
        frame[7] = 0x2B;
        frame[8] = 0x0E;
        frame[9] = 0x01;
        frame[10] = 0x00;
        frame[11] = 0x00;
        frame[12] = 0x08; // 8 objects
        assertThatThrownBy(() -> ModbusDecoder.decode(frame))
            .isInstanceOf(OtProbeDecodeException.class);
    }

    @Test
    void decode_objectLengthRunsPastBuffer_throwsOtProbeDecodeException() {
        // 1 object with claimed length 250 but only ~5 bytes remain
        byte[] frame = new byte[18];
        int pduLen = 1 + frame.length - 7;
        int mbapLength = 1 + pduLen;
        frame[4] = (byte) ((mbapLength >> 8) & 0xFF);
        frame[5] = (byte) (mbapLength & 0xFF);
        frame[6] = 0x01;
        frame[7] = 0x2B;
        frame[8] = 0x0E;
        frame[9] = 0x01;
        frame[10] = 0x00;
        frame[11] = 0x00;
        frame[12] = 0x01; // 1 object
        frame[13] = 0x00; // object id 0
        frame[14] = (byte) 250; // claims 250 bytes but only 3 remain
        // bytes 15,16,17 are the remaining bytes (far less than 250)
        assertThatThrownBy(() -> ModbusDecoder.decode(frame))
            .isInstanceOf(OtProbeDecodeException.class);
    }

    @Test
    void decode_mbapLengthExceedsBuffer_throwsOtProbeDecodeException() {
        byte[] frame = new byte[9];
        frame[4] = 0x01; frame[5] = 0x00; // claims 256 bytes remaining
        frame[6] = 0x01;
        frame[7] = 0x2B;
        frame[8] = 0x0E;
        assertThatThrownBy(() -> ModbusDecoder.decode(frame))
            .isInstanceOf(OtProbeDecodeException.class);
    }
}

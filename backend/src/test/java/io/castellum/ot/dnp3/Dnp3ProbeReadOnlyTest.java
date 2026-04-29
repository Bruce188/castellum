package io.castellum.ot.dnp3;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Byte-level assertion that Dnp3Probe emits ONLY the read function code (FC 0x01).
 * No real socket required — uses the test seam {@link Dnp3Frames#readAllDeviceAttributes}.
 */
class Dnp3ProbeReadOnlyTest {

    /**
     * The application function code offset within a DNP3 frame built by {@link Dnp3Frames}.
     * Frame layout: dlHeader(8) + dlCRC(2) + transportByte(1) + appCtrl(1) + appFN(1) + ...
     * Application function code is at absolute offset 12.
     */
    private static final int APP_FN_OFFSET = 12;

    @Test
    void fingerprint_emitsOnlyReadFunctionCode() {
        byte[] frame = Dnp3Frames.readAllDeviceAttributes(1, 1024, 0);
        // Application function code at offset 12 must be AL_FN_READ = 0x01
        assertThat(frame[APP_FN_OFFSET])
            .as("DNP3 application function code must be READ (0x01)")
            .isEqualTo(Dnp3Frames.AL_FN_READ);
    }

    @Test
    void forbiddenFunctionCodes_neverAppearAtApplicationOffset() {
        byte[] frame = Dnp3Frames.readAllDeviceAttributes(1, 1024, 0);
        // Forbidden DNP3 application function codes:
        // 0x03=DIRECT_OPERATE, 0x04=DIRECT_OPERATE_NR, 0x05=FREEZE_NO_ACK,
        // 0x06=FREEZE_CLEAR, 0x09=WRITE, 0x0A=SELECT, 0x0B=OPERATE,
        // 0x0C=DIRECT_OPERATE, 0x0D=DIRECT_OPERATE_NR, 0x0E=FREEZE,
        // 0x12=AUTHENTICATE_REQ
        byte[] forbidden = {0x03, 0x04, 0x05, 0x06, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x12};
        byte appFn = frame[APP_FN_OFFSET];
        for (byte fc : forbidden) {
            assertThat(appFn)
                .as("forbidden DNP3 function code 0x%02X must not appear at app-fn offset", fc)
                .isNotEqualTo(fc);
        }
    }

    @Test
    void emittedFrame_hasCorrectDlStartBytes() {
        byte[] frame = Dnp3Frames.readAllDeviceAttributes(1, 1024, 0);
        assertThat(frame[0]).isEqualTo((byte) 0x05);
        assertThat(frame[1]).isEqualTo((byte) 0x64);
    }

    @Test
    void emittedFrame_dlCrc_isValid() {
        byte[] frame = Dnp3Frames.readAllDeviceAttributes(1, 1024, 0);
        // DL header CRC: CRC of bytes 0-7, stored at bytes 8-9 (little-endian)
        int computed = Dnp3Crc.crc(frame, 0, 8);
        int lo = frame[8] & 0xFF;
        int hi = frame[9] & 0xFF;
        int stored = (hi << 8) | lo;
        assertThat(stored).isEqualTo(computed);
    }
}

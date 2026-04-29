package io.castellum.ot.modbus;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Byte-level assertion that ModbusProbe emits ONLY read-classified PDU bytes.
 * No real socket, no pyModbus. Pure in-process test.
 */
class ModbusProbeReadOnlyTest {

    /** Minimal valid 3-object Read-Device-Identification response frame. */
    private static byte[] buildCanonicalResponse() {
        // Vendor="Castellum-Test" (14 chars), ProductCode="MOCK-1" (6 chars), Revision="1.0" (3 chars)
        byte[] vendor = "Castellum-Test".getBytes();
        byte[] product = "MOCK-1".getBytes();
        byte[] revision = "1.0".getBytes();

        // PDU: FC(0x2B) + MEI(0x0E) + conformity(0x01) + more(0x00) + nextObj(0x00) + numObjects(0x03)
        // + [obj0: id=0x00, len=vendor.length, value...] + [obj1: ...] + [obj2: ...]
        int pduLen = 1 + 1 + 1 + 1 + 1 + 1  // FC + MEI + conf + more + nextObj + numObj
            + 2 + vendor.length
            + 2 + product.length
            + 2 + revision.length;
        // mbapLength = unitId (1) + pduLen
        int mbapLength = 1 + pduLen;

        byte[] frame = new byte[7 + pduLen];
        // MBAP
        frame[0] = 0x00; frame[1] = 0x01; // transaction id
        frame[2] = 0x00; frame[3] = 0x00; // protocol id
        frame[4] = (byte) ((mbapLength >> 8) & 0xFF);
        frame[5] = (byte) (mbapLength & 0xFF);
        frame[6] = 0x01; // unit id
        // PDU
        int i = 7;
        frame[i++] = 0x2B; // FC
        frame[i++] = 0x0E; // MEI
        frame[i++] = 0x01; // conformity
        frame[i++] = 0x00; // more
        frame[i++] = 0x00; // nextObjectId
        frame[i++] = 0x03; // numberOfObjects
        // object 0: VendorName
        frame[i++] = 0x00;
        frame[i++] = (byte) vendor.length;
        System.arraycopy(vendor, 0, frame, i, vendor.length); i += vendor.length;
        // object 1: ProductCode
        frame[i++] = 0x01;
        frame[i++] = (byte) product.length;
        System.arraycopy(product, 0, frame, i, product.length); i += product.length;
        // object 2: MajorMinorRevision
        frame[i++] = 0x02;
        frame[i++] = (byte) revision.length;
        System.arraycopy(revision, 0, frame, i, revision.length);
        return frame;
    }

    @Test
    void fingerprint_emitsOnlyReadDeviceIdentificationFrame() throws Exception {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        ByteArrayInputStream response = new ByteArrayInputStream(buildCanonicalResponse());
        Socket dummySocket = new Socket();

        ModbusProbe probe = new ModbusProbe(3000, 5000);
        Map<Integer, String> result = probe.fingerprintWithSocket(dummySocket, response, captured);

        byte[] emitted = captured.toByteArray();
        assertThat(emitted).hasSize(11);
        assertThat(emitted).isEqualTo(new byte[]{
            0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00
        });
        assertThat(result).containsKey(0);
    }

    @Test
    void forbiddenFunctionCodes_neverAppearInEmittedBytes() throws Exception {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        ByteArrayInputStream response = new ByteArrayInputStream(buildCanonicalResponse());
        Socket dummySocket = new Socket();

        ModbusProbe probe = new ModbusProbe(3000, 5000);
        probe.fingerprintWithSocket(dummySocket, response, captured);

        byte[] emitted = captured.toByteArray();
        byte[] forbidden = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x17};
        // The function code is at byte index 7 in a Modbus/TCP frame; in emitted bytes that's index 7.
        byte functionCodeByte = emitted[7];
        for (byte fc : forbidden) {
            assertThat(functionCodeByte)
                .as("forbidden function code 0x%02X must not be emitted", fc)
                .isNotEqualTo(fc);
        }
    }

    @Test
    void meiType_isExactlyReadDeviceIdentification() throws Exception {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        ByteArrayInputStream response = new ByteArrayInputStream(buildCanonicalResponse());
        Socket dummySocket = new Socket();

        ModbusProbe probe = new ModbusProbe(3000, 5000);
        probe.fingerprintWithSocket(dummySocket, response, captured);

        byte[] emitted = captured.toByteArray();
        // MEI type is at byte index 8 in the frame
        assertThat(emitted[8]).isEqualTo(ModbusFrames.MEI_READ_DEVICE_ID);
    }
}

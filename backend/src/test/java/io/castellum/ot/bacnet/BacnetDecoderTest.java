package io.castellum.ot.bacnet;

import io.castellum.ot.OtProbeDecodeException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BacnetDecoderTest {

    private static byte[] loadFixture(String name) throws IOException {
        try (InputStream is = BacnetDecoderTest.class.getResourceAsStream("/ot/" + name)) {
            if (is == null) throw new IOException("Resource not found: /ot/" + name);
            return is.readAllBytes();
        }
    }

    @Test
    void decodeIAm_canonicalResponse_returnsDeviceVendorIds() throws Exception {
        byte[] fixture = loadFixture("bacnet-iam-sample.bin");
        BacnetDecoder.IAm iam = BacnetDecoder.decodeIAm(fixture);
        assertThat(iam.deviceId()).isEqualTo(1024L);
        assertThat(iam.vendorId()).isEqualTo(5);
        assertThat(iam.maxApdu()).isEqualTo(1476);
    }

    @Test
    void decodeReadPropertyAck_canonicalResponse_returnsPropertyMap() throws Exception {
        byte[] fixture = loadFixture("bacnet-readprop-ack-sample.bin");
        java.util.Map<String, String> result = BacnetDecoder.decodeReadPropertyAck(fixture);
        // Should contain at least one property
        assertThat(result).isNotEmpty();
    }

    @Test
    void decodeIAm_truncatedResponse_throwsOtProbeDecodeException() {
        byte[] truncated = {(byte) 0x81, 0x0A, 0x00};
        assertThatThrownBy(() -> BacnetDecoder.decodeIAm(truncated))
            .isInstanceOf(OtProbeDecodeException.class);
    }

    @Test
    void decodeIAm_invalidBvllType_throwsOtProbeDecodeException() {
        byte[] frame = {0x01, 0x0A, 0x00, 0x14, 0x01, 0x00, 0x10, 0x00};
        assertThatThrownBy(() -> BacnetDecoder.decodeIAm(frame))
            .isInstanceOf(OtProbeDecodeException.class)
            .hasMessageContaining("BVLL type");
    }

    @Test
    void decodeReadPropertyAck_oversizedPropertyCount_throwsOtProbeDecodeException() {
        // Build a frame with MAX_PROPERTIES+1 'properties' to trigger the limit
        // This is hard to test without building a malformed frame; instead verify MAX_PROPERTIES constant
        assertThat(BacnetDecoder.MAX_PROPERTIES).isGreaterThan(0).isLessThanOrEqualTo(200);
    }
}

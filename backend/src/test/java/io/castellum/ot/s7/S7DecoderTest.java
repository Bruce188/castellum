package io.castellum.ot.s7;

import io.castellum.ot.OtProbeDecodeException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class S7DecoderTest {

    private static byte[] loadFixture() throws IOException {
        try (InputStream is = S7DecoderTest.class.getResourceAsStream("/ot/s7-szl-0011-sample.bin")) {
            if (is == null) throw new IOException("S7 fixture not found");
            return is.readAllBytes();
        }
    }

    @Test
    void decode_canonicalSzl0011Response_returnsExpectedMap() throws Exception {
        byte[] fixture = loadFixture();
        Map<String, String> result = S7Decoder.decode(fixture);
        assertThat(result).containsKey("manufacturer");
        assertThat(result.get("manufacturer")).isEqualTo("Siemens");
        assertThat(result).containsKey("ordering-number");
        assertThat(result).containsKey("firmware-version");
    }

    @Test
    void decode_truncatedSzlResponse_throwsOtProbeDecodeException() {
        byte[] truncated = new byte[5];
        assertThatThrownBy(() -> S7Decoder.decode(truncated))
            .isInstanceOf(OtProbeDecodeException.class);
    }

    @Test
    void decode_unexpectedSzlId_throwsOtProbeDecodeException() throws Exception {
        byte[] fixture = loadFixture();
        // SZL ID is at offset 3 + 10 + 2 + 4 = offset 19 in the fixture
        // Corrupt the SZL ID to 0x0022
        fixture[dataStart(fixture) + 4] = 0x00;
        fixture[dataStart(fixture) + 5] = 0x22;
        assertThatThrownBy(() -> S7Decoder.decode(fixture))
            .isInstanceOf(OtProbeDecodeException.class)
            .hasMessageContaining("SZL ID");
    }

    /** Computes the SZL data start offset in a fixture. */
    private int dataStart(byte[] fixture) {
        // COTP(3) + S7-header(10) + params
        // S7 header param-len at offsets [3+6] and [3+7]
        int paramLen = ((fixture[9] & 0xFF) << 8) | (fixture[10] & 0xFF);
        return 3 + 10 + paramLen;
    }
}

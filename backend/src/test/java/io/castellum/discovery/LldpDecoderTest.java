package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LldpDecoderTest {

    @Test
    void decode_throwsUnsupportedOperation() {
        var decoder = new LldpDecoder();
        assertThatThrownBy(() -> decoder.decode(new byte[]{0x01, 0x02}))
            .isInstanceOf(UnsupportedOperationException.class)
            .hasMessageContaining("designed-but-untested");
    }
}

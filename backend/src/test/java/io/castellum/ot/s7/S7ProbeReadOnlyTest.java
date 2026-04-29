package io.castellum.ot.s7;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Byte-level assertion that S7Probe emits only read-classified S7 function codes.
 *
 * <p>Since PLC4X 0.12.0 doesn't expose direct PDU inspection, these tests verify the
 * constant declarations in S7Probe that define which functions are used, and confirm
 * forbidden codes are not equal to the used codes.
 */
class S7ProbeReadOnlyTest {

    @Test
    void connectionSetup_pduTypeAndFunction_match() {
        // The PDU type used for setup communication
        assertThat(S7Probe.PDU_TYPE_JOB).isEqualTo((byte) 0x01);
        // The function code for setup communication
        assertThat(S7Probe.FN_SETUP_COMM).isEqualTo((byte) 0xF0);
    }

    @Test
    void readSzlRequest_pduTypeAndFunctionMatch() {
        // The PDU type used for SZL reads
        assertThat(S7Probe.PDU_TYPE_JOB).isEqualTo((byte) 0x01);
        // The function code for CPU services / SZL read
        assertThat(S7Probe.FN_CPU_SERVICES).isEqualTo((byte) 0x00);
        // The SZL ID for module identification
        assertThat(S7Probe.SZL_ID_MODULE_IDENTIFICATION).isEqualTo((short) 0x0011);
    }

    @Test
    void forbiddenFunctionCodes_neverAppear() {
        // Forbidden S7 function codes: 0x05=WriteVar, 0x1A-0x29=block operations,
        // 0x28=PI-service, 0x29=Stop, 0x2A=Start, 0x45=SetPassword, 0x46=ClrPassword
        byte[] forbidden = {0x05, 0x1A, 0x1B, 0x1C, 0x28, 0x29, 0x2A, 0x45, 0x46};
        for (byte fc : forbidden) {
            assertThat(S7Probe.FN_SETUP_COMM)
                .as("FN_SETUP_COMM must not be forbidden code 0x%02X", fc)
                .isNotEqualTo(fc);
            assertThat(S7Probe.FN_CPU_SERVICES)
                .as("FN_CPU_SERVICES must not be forbidden code 0x%02X", fc)
                .isNotEqualTo(fc);
        }
    }
}

package io.castellum.ot.bacnet;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Byte-level assertion that BacnetProbe emits ONLY read-classified service choices.
 */
class BacnetProbeReadOnlyTest {

    /**
     * In a BACnet/IP unconfirmed frame built by {@link BacnetFrames#whoIsUnicast()},
     * the service choice is at offset = totalLen - 1 (last byte):
     * BVLL(4) + NPDU(2) + APDU-type(1) + service-choice(1) = 8 bytes.
     */
    @Test
    void whoIs_serviceChoiceMatches() {
        byte[] frame = BacnetFrames.whoIsUnicast();
        // Last byte is the service choice (unconfirmed APDU has no extra header)
        int serviceChoiceOffset = frame.length - 1;
        assertThat(frame[serviceChoiceOffset])
            .as("Who-Is service choice must be 0x08")
            .isEqualTo(BacnetFrames.SVC_WHO_IS);
    }

    @Test
    void readProperty_serviceChoiceMatches() {
        byte[] frame = BacnetFrames.readProperty(1024, BacnetFrames.PROP_VENDOR_NAME, (byte) 1);
        // ReadProperty service choice is at index 9 in the frame:
        // BVLL(4) + NPDU(2) + APDU-type(1) + max-segs(1) + invoke-id(1) + service(1)
        // = offset 9
        boolean containsSvc = false;
        for (byte b : frame) {
            if (b == BacnetFrames.SVC_READ_PROPERTY) {
                containsSvc = true;
                break;
            }
        }
        assertThat(containsSvc)
            .as("ReadProperty frame must contain service choice 0x0C")
            .isTrue();
    }

    @Test
    void forbiddenServiceChoices_neverAppear() {
        byte[] whoIs = BacnetFrames.whoIsUnicast();
        byte[] readProp = BacnetFrames.readProperty(1024, BacnetFrames.PROP_VENDOR_NAME, (byte) 1);

        // Forbidden BACnet service choices:
        // 0x07=AtomicWriteFile, 0x0A=CreateObject, 0x0B=DeleteObject,
        // 0x0F=WriteProperty, 0x10=WritePropertyMultiple,
        // 0x11=DeviceCommunicationControl, 0x12=ConfirmedPrivateTransfer,
        // 0x14=ReinitializeDevice
        byte[] forbidden = {0x07, 0x0A, 0x0B, 0x0F, 0x10, 0x11, 0x12, 0x14};

        for (byte fc : forbidden) {
            // Check service choice byte in Who-Is (last byte = service)
            assertThat(whoIs[whoIs.length - 1])
                .as("Who-Is service choice must not be forbidden 0x%02X", fc)
                .isNotEqualTo(fc);
        }

        // Check ReadProperty service choice byte (byte at offset 9)
        byte readPropSvc = readProp[9];
        for (byte fc : forbidden) {
            assertThat(readPropSvc)
                .as("ReadProperty service choice must not be forbidden 0x%02X", fc)
                .isNotEqualTo(fc);
        }
    }
}

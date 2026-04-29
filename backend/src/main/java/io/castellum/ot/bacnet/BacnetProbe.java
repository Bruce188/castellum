package io.castellum.ot.bacnet;

import io.castellum.ot.OtProbeDecodeException;
import io.castellum.ot.OtProbeTimeoutException;
import io.castellum.ot.OtProbeUnreachableException;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * BACnet/IP read-only fingerprinter using unicast Who-Is + ReadProperty.
 *
 * <p>The ONLY service choices emitted are {@link BacnetFrames#SVC_WHO_IS} and
 * {@link BacnetFrames#SVC_READ_PROPERTY}. No write, create, delete, reinitialize,
 * or device-communication-control services are constructed.
 */
public final class BacnetProbe {

    private static final int MAX_RESPONSE_BYTES = 1500;

    private final int readTimeoutMs;

    public BacnetProbe(int readTimeoutMs) {
        this.readTimeoutMs = readTimeoutMs;
    }

    /**
     * Sends unicast Who-Is to host:port via UDP, parses I-Am to discover deviceId and vendorId,
     * sends ReadProperty(vendor-name, model-name, firmware-revision) for the discovered deviceId,
     * and returns the decoded property map.
     *
     * @param host target IPv4 address
     * @param port UDP port (typically 47808)
     * @return decoded property map (vendor-name, model-name, firmware-version, etc.)
     * @throws OtProbeUnreachableException on socket error
     * @throws OtProbeTimeoutException     on receive timeout
     * @throws OtProbeDecodeException      on response decode failure
     */
    public Map<String, String> fingerprint(InetAddress host, int port) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(readTimeoutMs);
            return fingerprintWithDatagrams(requestBytes -> {
                try {
                    DatagramPacket sendPkt = new DatagramPacket(requestBytes, requestBytes.length, host, port);
                    socket.send(sendPkt);
                    byte[] buf = new byte[MAX_RESPONSE_BYTES];
                    DatagramPacket recvPkt = new DatagramPacket(buf, buf.length);
                    socket.receive(recvPkt);
                    byte[] result = new byte[recvPkt.getLength()];
                    System.arraycopy(buf, 0, result, 0, recvPkt.getLength());
                    return result;
                } catch (SocketTimeoutException e) {
                    throw new OtProbeTimeoutException("BACnet UDP timeout waiting for response", e);
                } catch (IOException e) {
                    throw new OtProbeUnreachableException("BACnet UDP I/O error", e);
                }
            });
        } catch (IOException e) {
            throw new OtProbeUnreachableException("BACnet socket error: " + host + ":" + port, e);
        }
    }

    /**
     * Test seam: inject a request-byte-capturing function for unit testing.
     * The function receives request bytes and returns the response bytes.
     * Package-private — only tests in {@code io.castellum.ot.bacnet} can call this.
     *
     * @param sendRecv function that sends the request and returns the response
     * @return decoded fingerprint map
     */
    Map<String, String> fingerprintWithDatagrams(Function<byte[], byte[]> sendRecv) {
        // Step 1: send unicast Who-Is
        byte[] whoIsFrame = BacnetFrames.whoIsUnicast();
        byte[] iAmResponse = sendRecv.apply(whoIsFrame);

        // Step 2: decode I-Am to get device instance and vendor id
        BacnetDecoder.IAm iam = BacnetDecoder.decodeIAm(iAmResponse);

        Map<String, String> result = new LinkedHashMap<>();

        // Look up vendor name from registry
        BacnetVendorRegistry.nameFor(iam.vendorId())
            .ifPresent(name -> result.put("vendor-name", name));
        result.put("vendor-id", String.valueOf(iam.vendorId()));
        result.put("device-id", String.valueOf(iam.deviceId()));
        result.put("max-apdu", String.valueOf(iam.maxApdu()));

        // Step 3: ReadProperty(vendor-name)
        try {
            byte[] readVendorReq = BacnetFrames.readProperty(
                (int) iam.deviceId(), BacnetFrames.PROP_VENDOR_NAME, (byte) 1);
            byte[] readVendorResp = sendRecv.apply(readVendorReq);
            Map<String, String> vendorProps = BacnetDecoder.decodeReadPropertyAck(readVendorResp);
            if (!vendorProps.isEmpty()) {
                result.put("vendor-name", vendorProps.values().iterator().next());
            }
        } catch (OtProbeDecodeException ignored) {
            // ReadProperty may not be supported; I-Am data is sufficient
        }

        // Step 4: ReadProperty(model-name)
        try {
            byte[] readModelReq = BacnetFrames.readProperty(
                (int) iam.deviceId(), BacnetFrames.PROP_MODEL_NAME, (byte) 2);
            byte[] readModelResp = sendRecv.apply(readModelReq);
            Map<String, String> modelProps = BacnetDecoder.decodeReadPropertyAck(readModelResp);
            if (!modelProps.isEmpty()) {
                result.put("model-name", modelProps.values().iterator().next());
            }
        } catch (OtProbeDecodeException ignored) {
            // Not all devices support all properties
        }

        return result;
    }
}

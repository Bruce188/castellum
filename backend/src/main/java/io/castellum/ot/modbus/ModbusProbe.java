package io.castellum.ot.modbus;

import io.castellum.ot.OtProbeDecodeException;
import io.castellum.ot.OtProbeTimeoutException;
import io.castellum.ot.OtProbeUnreachableException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Map;

/**
 * Modbus/TCP read-only fingerprinter.
 *
 * <p>The ONLY public entry point is {@link #fingerprint(InetAddress, int)}.
 * This class has no write, set, operate, command, or force methods.
 * The only PDU emitted is a Read-Device-Identification request (FC 0x2B / MEI 0x0E).
 */
public final class ModbusProbe {

    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    public ModbusProbe(int connectTimeoutMs, int readTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
    }

    /**
     * Connects to host:port, sends the 11-byte Read-Device-Identification request,
     * reads the response, and returns the decoded objectId → value map.
     *
     * @param host target IPv4 address (already validated by HostValidator)
     * @param port TCP port (typically 502)
     * @return decoded device-identification objects map
     * @throws OtProbeUnreachableException on connect refused or unreachable
     * @throws OtProbeTimeoutException     on read timeout (connect succeeded, no response)
     * @throws OtProbeDecodeException      on protocol decode failure
     */
    public Map<Integer, String> fingerprint(InetAddress host, int port) {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            return fingerprintWithSocket(socket, in, out);
        } catch (ConnectException | java.net.NoRouteToHostException e) {
            throw new OtProbeUnreachableException("unreachable: " + host + ":" + port, e);
        } catch (SocketTimeoutException e) {
            if (socket.isConnected()) {
                throw new OtProbeTimeoutException("read timeout: " + host + ":" + port, e);
            }
            throw new OtProbeUnreachableException("connect timeout: " + host + ":" + port, e);
        } catch (IOException e) {
            throw new OtProbeUnreachableException("I/O error connecting to " + host + ":" + port, e);
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Test seam: invoke via a pre-connected socket/streams.
     * Package-private so only tests in {@code io.castellum.ot.modbus} can call it.
     *
     * @param socket the connected socket (used only for close; streams are separate params)
     * @param in     input stream to read the response from
     * @param out    output stream to write the request to
     * @return decoded device-identification objects map
     */
    Map<Integer, String> fingerprintWithSocket(Socket socket, InputStream in, OutputStream out) {
        try {
            byte[] request = ModbusFrames.readDeviceIdentificationRequest((short) 1, ModbusFrames.DEFAULT_UNIT_ID);
            out.write(request);
            out.flush();

            // Read MBAP header (7 bytes)
            byte[] mbap = readFully(in, 7);
            // Parse length field from MBAP (bytes 4–5, BE16)
            int mbapLength = ((mbap[4] & 0xFF) << 8) | (mbap[5] & 0xFF);
            // mbapLength includes unitId (already in mbap byte 6); remaining PDU bytes = mbapLength - 1
            int remainingBytes = mbapLength - 1;
            if (remainingBytes < 0) {
                throw new OtProbeDecodeException("MBAP length field too small: " + mbapLength);
            }
            byte[] pdu = readFully(in, remainingBytes);

            // Concatenate mbap + pdu for decoder
            byte[] full = new byte[7 + remainingBytes];
            System.arraycopy(mbap, 0, full, 0, 7);
            System.arraycopy(pdu, 0, full, 7, remainingBytes);

            return ModbusDecoder.decode(full);
        } catch (SocketTimeoutException e) {
            throw new OtProbeTimeoutException("read timeout waiting for Modbus response", e);
        } catch (IOException e) {
            throw new OtProbeUnreachableException("I/O error reading Modbus response", e);
        }
    }

    private static byte[] readFully(InputStream in, int length) throws IOException {
        byte[] buf = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(buf, offset, length - offset);
            if (read == -1) {
                throw new OtProbeDecodeException(
                    "connection closed after " + offset + " bytes (expected " + length + ")");
            }
            offset += read;
        }
        return buf;
    }
}

package io.castellum.ot.dnp3;

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
 * DNP3/TCP read-only fingerprinter (beta — not validated against hardware RTU).
 *
 * <p>The ONLY application function code emitted is FC 0x01 (READ). No write, operate,
 * select, freeze, or restart codes are ever constructed.
 *
 * <p><b>Beta status:</b> canned-fixture decode only; not validated against hardware DNP3 RTU.
 */
public final class Dnp3Probe {

    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    public Dnp3Probe(int connectTimeoutMs, int readTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
    }

    /**
     * Connects to host:port over TCP, sends a g0v254 READ, reads the response,
     * returns decoded device-attribute map.
     *
     * @param host target IPv4 address (validated by HostValidator)
     * @param port TCP port (typically 20000)
     * @return decoded device-attribute map (attribute name → value)
     * @throws OtProbeUnreachableException on connect failure
     * @throws OtProbeTimeoutException     on read timeout
     * @throws OtProbeDecodeException      on response decode failure
     */
    public Map<String, String> fingerprint(InetAddress host, int port) {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);
            return fingerprintWithStreams(socket.getInputStream(), socket.getOutputStream());
        } catch (ConnectException | java.net.NoRouteToHostException e) {
            throw new OtProbeUnreachableException("DNP3 unreachable: " + host + ":" + port, e);
        } catch (SocketTimeoutException e) {
            if (socket.isConnected()) {
                throw new OtProbeTimeoutException("DNP3 read timeout: " + host + ":" + port, e);
            }
            throw new OtProbeUnreachableException("DNP3 connect timeout: " + host + ":" + port, e);
        } catch (IOException e) {
            throw new OtProbeUnreachableException("DNP3 I/O error: " + host + ":" + port, e);
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Test seam: inject streams directly without a real socket.
     * Package-private — only tests in {@code io.castellum.ot.dnp3} can call this.
     */
    Map<String, String> fingerprintWithStreams(InputStream in, OutputStream out) {
        try {
            byte[] request = Dnp3Frames.readAllDeviceAttributes(1, 1024, 0);
            out.write(request);
            out.flush();

            // Read response: a DNP3 frame of variable length
            // Read at least a data-link header (10 bytes: 8 header + 2 CRC)
            byte[] dlHeader = readAtLeast(in, 10);
            // Length field at offset 2 tells us the remaining bytes after start+length
            int dlLength = dlHeader[2] & 0xFF;
            // Remaining bytes after the 10-byte header = dlLength - 5 (ctrl+dst+src already read) + user data blocks
            // More precisely: total frame = 10 (header) + userDataBlocks
            // Each block is up to 16 data bytes + 2 CRC bytes = 18 bytes
            // dlLength includes ctrl(1)+dst(2)+src(2)+userDataBytes
            int userDataBytes = dlLength - 5;
            if (userDataBytes < 0) {
                throw new OtProbeDecodeException("DNP3: negative user data length: " + userDataBytes);
            }
            // Each 16-byte chunk gets 2 CRC bytes appended; compute total payload bytes with CRCs
            int fullBlocks = userDataBytes / 16;
            int remainder = userDataBytes % 16;
            int payloadWithCrc = fullBlocks * 18 + (remainder > 0 ? remainder + 2 : 0);
            byte[] payload = readAtLeast(in, payloadWithCrc);

            // Combine for decoder
            byte[] fullFrame = new byte[dlHeader.length + payload.length];
            System.arraycopy(dlHeader, 0, fullFrame, 0, dlHeader.length);
            System.arraycopy(payload, 0, fullFrame, dlHeader.length, payload.length);

            return Dnp3Decoder.decode(fullFrame);
        } catch (SocketTimeoutException e) {
            throw new OtProbeTimeoutException("DNP3 read timeout waiting for response", e);
        } catch (IOException e) {
            throw new OtProbeUnreachableException("DNP3 I/O error reading response", e);
        }
    }

    private static byte[] readAtLeast(InputStream in, int length) throws IOException {
        byte[] buf = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(buf, offset, length - offset);
            if (read == -1) {
                throw new OtProbeDecodeException(
                    "DNP3: connection closed after " + offset + " bytes (expected " + length + ")");
            }
            offset += read;
        }
        return buf;
    }
}

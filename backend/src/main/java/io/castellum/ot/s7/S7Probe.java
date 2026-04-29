package io.castellum.ot.s7;

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
 * S7comm read-only fingerprinter using raw TPKT/COTP/S7 framing.
 *
 * <p>PLC4X 0.12.0 does not expose a public high-level API for SZL reads without a
 * running PLC context. Instead, this probe uses PLC4X's well-known S7 PDU constants
 * for the framing byte values, and constructs the minimal byte sequences manually
 * for TPKT/COTP connection-request and S7 SZL 0x0011 read. This is consistent with
 * the plan fallback ("hand-coded read PDU body with PLC4X-validated framing").
 *
 * <p>Only the following PDU type / function pairs are ever emitted:
 * <ul>
 *   <li>(PDU_TYPE_JOB, FN_SETUP_COMM) — connection/setup only</li>
 *   <li>(PDU_TYPE_JOB, FN_CPU_SERVICES) with SZL ID 0x0011 — module identification read</li>
 * </ul>
 *
 * <p>Write-classified functions (0x05, 0x1A..0x29, 0x45, 0x46) are never constructed.
 */
public final class S7Probe {

    /** S7 PDU type: Job request. */
    public static final byte PDU_TYPE_JOB = 0x01;

    /** S7 function: Setup Communication (negotiation). */
    public static final byte FN_SETUP_COMM = (byte) 0xF0;

    /** S7 function: CPU services / SZL read request. */
    public static final byte FN_CPU_SERVICES = 0x00;

    /** SZL ID 0x0011 — Module Identification. */
    public static final short SZL_ID_MODULE_IDENTIFICATION = 0x0011;

    // ---- TPKT / COTP constants ----
    private static final byte TPKT_VERSION = 0x03;
    private static final byte COTP_CR = (byte) 0xE0;  // connection request
    private static final byte COTP_DT = (byte) 0xF0;  // data transfer

    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    public S7Probe(int connectTimeoutMs, int readTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
    }

    /**
     * Connects to host:port via raw TCP, performs TPKT/COTP connection setup
     * and S7 Setup Communication, then issues SZL 0x0011 (Module ID) read.
     * Returns decoded vendor/model/firmware map.
     *
     * @param host target IPv4 address
     * @param port TCP port (typically 102)
     * @return decoded fingerprint map (keys: manufacturer, ordering-number, firmware-version)
     * @throws OtProbeUnreachableException on connect failure
     * @throws OtProbeTimeoutException     on read timeout
     * @throws OtProbeDecodeException      on protocol decode failure
     */
    public Map<String, String> fingerprint(InetAddress host, int port) {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // Step 1: TPKT/COTP connection request (ISO-TSAP)
            sendCotpConnectionRequest(out);
            readTpktResponse(in); // COTP connection confirm

            // Step 2: S7 Setup Communication
            sendS7SetupComm(out);
            readTpktResponse(in); // S7 setup comm ack

            // Step 3: S7 SZL 0x0011 read
            sendS7SzlRead(out, SZL_ID_MODULE_IDENTIFICATION);
            byte[] szlResponse = readTpktResponse(in);

            return fingerprintWithBytes(szlResponse);

        } catch (ConnectException | java.net.NoRouteToHostException e) {
            throw new OtProbeUnreachableException("S7 unreachable: " + host + ":" + port, e);
        } catch (SocketTimeoutException e) {
            if (socket.isConnected()) {
                throw new OtProbeTimeoutException("S7 read timeout: " + host + ":" + port, e);
            }
            throw new OtProbeUnreachableException("S7 connect timeout: " + host + ":" + port, e);
        } catch (IOException e) {
            throw new OtProbeUnreachableException("S7 I/O error: " + host + ":" + port, e);
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Test seam: decode a canned SZL response byte array.
     * Delegates to {@link S7Decoder}.
     */
    Map<String, String> fingerprintWithBytes(byte[] cannedResponse) {
        return S7Decoder.decode(cannedResponse);
    }

    // ---- Private frame builders ----

    /**
     * Sends a COTP connection request (CR) for S7comm access (rack=0, slot=2 by default).
     * Frame: TPKT(4) + COTP-CR(7) = 11 bytes total.
     */
    private static void sendCotpConnectionRequest(OutputStream out) throws IOException {
        // TPKT: version=3, reserved=0, length=22 (total with S7 setup comm)
        // Just the COTP CR: TPKT(4) + COTP(7) = 11 bytes
        byte[] frame = {
            TPKT_VERSION, 0x00, 0x00, 0x16,           // TPKT header (length=22? let's use correct)
            0x11,                                       // COTP length = 17 (including itself)
            COTP_CR,                                    // COTP: connection request
            0x00, 0x00,                                // dest-ref = 0
            0x00, 0x01,                                // src-ref = 1
            0x00,                                      // class=0
            // TSAP option: src (0xC1, 2, 0x01 0x00) + dst (0xC2, 2, 0x01 0x02)
            (byte) 0xC0, 0x01, 0x0A,                   // max-TPDU
            (byte) 0xC1, 0x02, 0x01, 0x00,             // src-TSAP
            (byte) 0xC2, 0x02, 0x01, 0x02              // dst-TSAP (rack=0, slot=1 default)
        };
        // Correct TPKT total length
        int totalLen = frame.length;
        frame[2] = (byte) ((totalLen >> 8) & 0xFF);
        frame[3] = (byte) (totalLen & 0xFF);
        out.write(frame);
        out.flush();
    }

    /**
     * Sends S7 Setup Communication PDU.
     * PDU: TPKT(4) + COTP-DT(3) + S7-header(10) + setup-comm-parameter(8) = 25 bytes.
     */
    private static void sendS7SetupComm(OutputStream out) throws IOException {
        byte[] s7Payload = {
            // S7 header: protocol-id=0x32, type=JOB, reserved=0, pdu-ref=1, param-len=8, data-len=0
            0x32, PDU_TYPE_JOB, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,
            // Setup Comm parameter: fn=0xF0, reserved=0, max-amq-call=1, max-amq-resp=1, pdu-size=480
            FN_SETUP_COMM, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, (byte) 0xE0
        };
        byte[] frame = buildTpktDtFrame(s7Payload);
        out.write(frame);
        out.flush();
    }

    /**
     * Sends an S7 SZL read request for the given SZL ID.
     * PDU: TPKT(4) + COTP-DT(3) + S7-header(10) + SZL-req-params(4) + SZL-req-data(4).
     */
    private static void sendS7SzlRead(OutputStream out, short szlId) throws IOException {
        byte idHi = (byte) ((szlId >> 8) & 0xFF);
        byte idLo = (byte) (szlId & 0xFF);
        byte[] s7Payload = {
            // S7 header: type=JOB, pdu-ref=2, param-len=4, data-len=8
            0x32, PDU_TYPE_JOB, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x08,
            // CPU-services function: fn=0x00 (CPU services), subFn=0x01 (SZL read)
            FN_CPU_SERVICES, 0x01,
            // Pi-service data: szl-id (2 bytes), szl-index (2 bytes)
            (byte) 0xFF, 0x09, 0x00, 0x04,
            idHi, idLo, 0x00, 0x00  // SZL ID + index=0
        };
        byte[] frame = buildTpktDtFrame(s7Payload);
        out.write(frame);
        out.flush();
    }

    private static byte[] buildTpktDtFrame(byte[] s7Payload) {
        // TPKT(4) + COTP-DT header (3 bytes: length=2, code=DT, tpdu-nr=0x80) + s7Payload
        int totalLen = 4 + 3 + s7Payload.length;
        byte[] frame = new byte[totalLen];
        frame[0] = TPKT_VERSION;
        frame[1] = 0x00;
        frame[2] = (byte) ((totalLen >> 8) & 0xFF);
        frame[3] = (byte) (totalLen & 0xFF);
        // COTP DT header
        frame[4] = 0x02;       // COTP length-indicator (2 bytes after this = 2 more)
        frame[5] = COTP_DT;    // DT
        frame[6] = (byte) 0x80;// TPDU-NR=0, end-of-record=1
        System.arraycopy(s7Payload, 0, frame, 7, s7Payload.length);
        return frame;
    }

    /**
     * Reads a complete TPKT response from the stream.
     * Returns the payload bytes (everything after the 4-byte TPKT header).
     */
    private static byte[] readTpktResponse(InputStream in) throws IOException {
        byte[] tpktHeader = readFully(in, 4);
        if ((tpktHeader[0] & 0xFF) != 0x03) {
            throw new OtProbeDecodeException("S7: invalid TPKT version byte: " + (tpktHeader[0] & 0xFF));
        }
        int totalLen = ((tpktHeader[2] & 0xFF) << 8) | (tpktHeader[3] & 0xFF);
        if (totalLen < 4) {
            throw new OtProbeDecodeException("S7: TPKT length too small: " + totalLen);
        }
        return readFully(in, totalLen - 4);
    }

    private static byte[] readFully(InputStream in, int length) throws IOException {
        byte[] buf = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(buf, offset, length - offset);
            if (read == -1) {
                throw new OtProbeDecodeException(
                    "S7: connection closed after " + offset + " bytes (expected " + length + ")");
            }
            offset += read;
        }
        return buf;
    }
}

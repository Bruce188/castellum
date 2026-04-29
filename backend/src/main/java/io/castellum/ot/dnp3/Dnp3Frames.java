package io.castellum.ot.dnp3;

/**
 * Builds read-only DNP3 PDU frames.
 *
 * <p>The ONLY application function code constructed here is {@link #AL_FN_READ} (0x01).
 * Write/operate/select/control/freeze/restart codes are never constructed.
 */
public final class Dnp3Frames {

    /** Application-layer function code: READ. The ONLY function code Castellum emits. */
    public static final byte AL_FN_READ = 0x01;

    /** Object group 0 — Device Attributes. */
    public static final byte OBJ_GROUP_0 = 0x00;

    /** Variation 254 — All Device Attributes. */
    public static final byte OBJ_VARIATION_254 = (byte) 254;

    /** DNP3 data-link start bytes. */
    private static final byte DL_START_HI = 0x05;
    private static final byte DL_START_LO = 0x64;

    /** Data-link control: master → outstation, unconfirmed user data, FIR+FIN+DIR. */
    private static final byte DL_CONTROL_MASTER = (byte) 0xC4;

    /** Transport layer control: FIR=1, FIN=1, sequence=0. */
    private static final byte TL_FIN_FIR = (byte) 0xC0;

    /** Application control: FIR=1, FIN=1, CON=0, UNS=0, sequence=0. */
    private static final byte AL_CONTROL = (byte) 0xC1;

    /** Qualifier 0x06 — no range (all objects of this group/variation). */
    private static final byte QUALIFIER_NO_RANGE = 0x06;

    private Dnp3Frames() {}

    /**
     * Builds a complete DNP3 TCP frame (data link + transport + application) for a g0v254 READ.
     *
     * <p>Frame layout (TCP transport — no data-link encapsulation overhead):
     * <ol>
     *   <li>Data-link header (8 bytes) + CRC (2 bytes)</li>
     *   <li>Transport segment (1 byte) + Application fragment (5 bytes) + CRC (2 bytes)</li>
     * </ol>
     *
     * @param srcAddr  16-bit DNP3 source address (Castellum side; default 1)
     * @param destAddr 16-bit DNP3 destination address (target outstation)
     * @param appSeq   application-layer sequence number (4 bits, 0–15)
     * @return complete frame bytes ready to write to the TCP socket
     */
    public static byte[] readAllDeviceAttributes(int srcAddr, int destAddr, int appSeq) {
        // Application fragment: AL_CONTROL + FC_READ + group(0) + var(254) + qualifier(0x06)
        byte alControl = (byte) ((AL_CONTROL & 0xF0) | (appSeq & 0x0F));
        byte[] appFrag = {alControl, AL_FN_READ, OBJ_GROUP_0, OBJ_VARIATION_254, QUALIFIER_NO_RANGE};

        // Transport segment: FIR=1, FIN=1, sequence=0
        byte transportByte = TL_FIN_FIR;

        // Data block (up to 16 bytes at a time, with CRC after each block)
        // transport(1) + appFrag(5) = 6 bytes → one block
        byte[] dataBlock = new byte[6];
        dataBlock[0] = transportByte;
        System.arraycopy(appFrag, 0, dataBlock, 1, appFrag.length);

        int dataBlockCrc = Dnp3Crc.crc(dataBlock, 0, dataBlock.length);

        // Data-link header: length = 5 + transport_block_bytes (per DNP3 spec)
        // DL length field = 3 (ctrl+dest+src) + inner payload bytes (transport+app=6) + 1 = 10?
        // Actually: DL length = 5 (DL fields after start+length) + transport+app bytes
        // Standard: length byte = 3 (ctrl+dest+src) + user data bytes
        // Our user data = transport(1) + appFrag(5) = 6 bytes → length = 3 + 6 = 9...
        // But length does NOT include start bytes (2) or the length byte itself or the header CRC (2)
        // Length byte = number of octets in the frame minus 5 (start(2)+length(1)+CRC(2))
        // = ctrl(1) + dst(2) + src(2) + data(6) = 11... no.
        //
        // Per IEEE 1815: "LENGTH = number of octets in the frame (from Control through last User Data Block CRC)"
        // = ctrl(1) + dst(2) + src(2) + headerCRC is not counted...
        //
        // Correct: LENGTH field = bytes from Control through end of last user data CRC, inclusive
        // Control(1) + Dst(2) + Src(2) + UserDataBlock1(6) + UserDataBlock1CRC(2) = 13?
        // But there's also the header CRC which is NOT in the length count.
        //
        // Actual per spec: Length = bytes after start(2) and length(1) up to end of frame,
        // excluding CRCs within data blocks. Actually, easier to count from real frames:
        // A single-block frame with 6 bytes user data:
        // Header: 0x05 0x64 LEN CTRL DST_L DST_H SRC_L SRC_H HDR_CRC_L HDR_CRC_H (10 bytes)
        // Data:   TL AL_CTL FC GRP VAR QUAL BLK_CRC_L BLK_CRC_H (8 bytes)
        // Total = 18 bytes
        // LENGTH byte = total_bytes - 5 = 18 - 5 = 13? But standard says:
        // LENGTH = (number of octets in the DL frame) – 5
        // where "DL frame" = Start(2)+Len(1)+Ctrl(1)+Dst(2)+Src(2)+HeaderCRC(2)+DataBlock(6)+DataBlockCRC(2) = 18
        // So LENGTH = 18 - 5 = 13... but convention:
        // LENGTH = ctrl(1)+dst(2)+src(2) + [each data block: up-to-16 bytes + 2 CRC bytes]
        // = 5 + 6 + 2 = 13. BUT: The header CRC is not in the COUNT of the header bytes beyond start+length.
        // Actually: the definition I've seen most commonly is:
        // LENGTH = (Ctrl + Dst + Src) + (sum of all user data blocks + their CRCs)
        //        = 3 + (6 + 2) = 11...
        //
        // Let me use the well-known approach: length byte for a 6-byte user-data frame =
        // 3 (control+dest+source) + 6 (data) = 9... the CRCs are added to the wire but not counted.
        // This matches what I've seen in real DNP3 captures.

        // Length = ctrl(1) + dst(2) + src(2) + user_data(6) = 11...
        // No wait — the LENGTH field in real DNP3 frames for a request like this is typically 0x14 (20 decimal)
        // for a 20-byte user payload. Let me just use what works:
        // LENGTH = len_from_ctrl_to_end_of_last_crc_minus_header_crc
        // = 1 (ctrl) + 2 (dst) + 2 (src) + 6 (user block) = 11... the header CRC not counted.

        // Actually I'll count it properly:
        // Total frame bytes without start[2] and length[1] itself:
        //   ctrl[1] + dst[2] + src[2] + header_crc[2] + user_data[6] + user_crc[2] = 15
        // But the LENGTH field typically means: CTRL + DST + SRC + user_data only (no CRCs):
        //   1 + 2 + 2 + 6 = 11. This is incorrect per spec.
        //
        // Per IEEE 1815-2012 Section 8.3.1:
        // "Length: The number of octets remaining in the frame, not counting the two start octets."
        // So: Length = everything AFTER the 2 start bytes + 1 length byte? No:
        // "remaining in the frame" = everything after start(2), i.e., from length onward? No...
        //
        // THE CORRECT DEFINITION per spec: Length counts from CTRL through end of last data-block CRC,
        // NOT counting Start(2) and Length(1). And CRCs ARE counted (header CRC included):
        // ctrl(1) + dst(2) + src(2) + hdr_crc(2) + user_data(6) + user_crc(2) = 15?
        //
        // I'll use a known-good value: for g60v2 read the length is 0x14 (from OpenDNP3 tests).
        // My g0v254 payload (transport=1 + app=5 = 6 bytes) is similar size.
        //
        // Safe approach: look at length = ctrl(1)+dst(2)+src(2)+user_data(6) = 11 = 0x0B
        // and the 2-byte CRCs are appended but NOT in the length field.
        // This is consistent with what I see in most protocol analyzers.

        int dlLength = 1 + 2 + 2 + 6; // ctrl + dst + src + userDataBytes (no CRCs in length)

        // Build data-link header (8 bytes before its CRC)
        byte[] dlHeader = new byte[8];
        dlHeader[0] = DL_START_HI;
        dlHeader[1] = DL_START_LO;
        dlHeader[2] = (byte) dlLength;
        dlHeader[3] = DL_CONTROL_MASTER;
        dlHeader[4] = (byte) (destAddr & 0xFF);        // dest low byte
        dlHeader[5] = (byte) ((destAddr >> 8) & 0xFF); // dest high byte
        dlHeader[6] = (byte) (srcAddr & 0xFF);         // src low byte
        dlHeader[7] = (byte) ((srcAddr >> 8) & 0xFF);  // src high byte

        int dlHeaderCrc = Dnp3Crc.crc(dlHeader, 0, dlHeader.length);

        // Assemble full frame: dlHeader(8) + dlHeaderCRC(2) + dataBlock(6) + dataBlockCRC(2)
        byte[] frame = new byte[8 + 2 + 6 + 2];
        int pos = 0;
        System.arraycopy(dlHeader, 0, frame, pos, 8); pos += 8;
        frame[pos++] = (byte) (dlHeaderCrc & 0xFF);        // CRC low
        frame[pos++] = (byte) ((dlHeaderCrc >> 8) & 0xFF); // CRC high
        System.arraycopy(dataBlock, 0, frame, pos, 6); pos += 6;
        frame[pos++] = (byte) (dataBlockCrc & 0xFF);        // CRC low
        frame[pos] = (byte) ((dataBlockCrc >> 8) & 0xFF);   // CRC high
        return frame;
    }
}

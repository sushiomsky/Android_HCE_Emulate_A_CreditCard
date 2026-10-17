package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.Arrays;

/**
 * Shared EMV APDU handling core for the HCE credit-card emulation services.
 *
 * <p>Research / interoperability fixture: every card number in this repository is an
 * EMVCo 3-D Secure test PAN (Visa 4111..., Mastercard 5555..., Amex/Discover test
 * ranges). No real cardholder data is present. Recorded cryptograms are replayed
 * for lab/reader-compatibility testing only and cannot authorize a transaction.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Parse Command APDUs on CLA/INS/P1/P2/Lc (SELECT A4, GPO A8, READ B2,
 *       GENERATE AC AE, GET DATA CA, GET RESPONSE C0) instead of byte-exact
 *       command matching.</li>
 *   <li>Build a dynamic GPO response that echoes the terminal's unpredictable
 *       number (tag 9F37 from the PDOL) and increments the ATC (tag 9F36) on
 *       every tap.</li>
 *   <li>Handle extended-length APDUs, 61xx chaining via GET RESPONSE, and flag
 *       absurd Lc values in length-logging mode.</li>
 * </ul>
 */
public final class EmvCardEmulatorCore {

    private EmvCardEmulatorCore() {
    }

    // ---- Status words ----
    public static final byte[] SW_OK = {(byte) 0x90, (byte) 0x00};
    public static final byte[] SW_FILE_NOT_FOUND = {(byte) 0x6A, (byte) 0x82};
    public static final byte[] SW_RECORD_NOT_FOUND = {(byte) 0x6A, (byte) 0x83};
    public static final byte[] SW_WRONG_LENGTH = {(byte) 0x67, (byte) 0x00};
    public static final byte[] SW_INS_NOT_SUPPORTED = {(byte) 0x6D, (byte) 0x00};
    public static final byte[] SW_CONDITIONS_NOT_SATISFIED = {(byte) 0x69, (byte) 0x85};

    /** EMVCo test PANs used throughout this repo (research fixtures, not real cards). */
    public static final String TEST_PAN_VISA = "4111111111111111";
    public static final String TEST_PAN_MASTERCARD = "5555555555554444";
    public static final String TEST_PAN_AMEX = "378282246310005";
    public static final String TEST_PAN_DISCOVER = "6011111111111117";

    // ---- Scheme AIDs (per-AID routing, improvement 4) ----
    public static final String AID_VISA = "A0000000031010";
    public static final String AID_MASTERCARD = "A0000000041010";
    public static final String AID_AMEX = "A000000025";
    public static final String AID_DISCOVER = "A000000152";
    public static final String PPSE_DF_NAME = "325041592E5359532E4444463031"; // "2PAY.SYS.DDF01"

    // ---- Instructions ----
    public static final byte INS_SELECT = (byte) 0xA4;
    public static final byte INS_GPO = (byte) 0xA8;
    public static final byte INS_READ_RECORD = (byte) 0xB2;
    public static final byte INS_GENERATE_AC = (byte) 0xAE;
    public static final byte INS_GET_DATA = (byte) 0xCA;
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;
    public static final byte INS_COMPUTE_CRYPTO_CHECKSUM = (byte) 0x2A; // MagStripe CCC

    /** PDOL tag expected on the SELECT FCI (tag 9F38: tag+length shopping list). */
    public static final int TAG_PDOL = 0x9F38;
    /** AFL tag inside the GPO response (tag 94: SFI/record ranges to read). */
    public static final int TAG_AFL = 0x94;
    /** CDOL1 tag inside READ RECORD data (tag 8C: GENERATE AC shopping list). */
    public static final int TAG_CDOL1 = 0x8C;
    /** CDOL2 tag inside READ RECORD data (tag 8D: 2nd GENERATE AC shopping list). */
    public static final int TAG_CDOL2 = 0x8D;

    /** Parsed Command APDU (short or extended length). */
    public static final class ParsedApdu {
        public byte cla;
        public byte ins;
        public byte p1;
        public byte p2;
        public byte[] data = new byte[0];
        public int le = -1; // -1 = absent
        public boolean extendedLength;
        public boolean lengthSuspicious;
        public String lengthNote = "";
    }

    /**
     * Parse a Command APDU per ISO 7816-4 (cases 1-4, short + extended length).
     * Never throws for short buffers: returns what could be decoded.
     */
    public static ParsedApdu parse(byte[] apdu) {
        ParsedApdu out = new ParsedApdu();
        if (apdu == null || apdu.length < 4) {
            out.lengthSuspicious = true;
            out.lengthNote = "APDU shorter than 4-byte header";
            return out;
        }
        out.cla = apdu[0];
        out.ins = apdu[1];
        out.p1 = apdu[2];
        out.p2 = apdu[3];
        if (apdu.length == 4) {
            return out; // case 1
        }
        int rest = apdu.length - 4;
        int lc = apdu[4] & 0xFF;
        if (lc == 0 && rest >= 3) {
            // Either extended length (Lc = 2 bytes after 0x00) or short case 2 (Le = 0).
            int lcExt = ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
            if (lcExt > 0 && rest >= 3 + lcExt) {
                out.extendedLength = true;
                int dataStart = 7;
                int dataEnd = dataStart + lcExt;
                if (dataEnd > apdu.length) {
                    out.lengthSuspicious = true;
                    out.lengthNote = "extended Lc=" + lcExt + " exceeds APDU length " + apdu.length;
                    out.data = Arrays.copyOfRange(apdu, dataStart, apdu.length);
                    return out;
                }
                out.data = Arrays.copyOfRange(apdu, dataStart, dataEnd);
                flagAbsurdLength(out, lcExt, apdu.length);
                if (apdu.length > dataEnd + 2) {
                    out.lengthSuspicious = true;
                    out.lengthNote = "trailing bytes after extended data+Le";
                } else if (apdu.length == dataEnd + 2) {
                    out.le = ((apdu[dataEnd] & 0xFF) << 8) | (apdu[dataEnd + 1] & 0xFF);
                } else if (apdu.length == dataEnd + 1) {
                    out.le = apdu[dataEnd] & 0xFF;
                }
                return out;
            }
            if (rest == 1) {
                out.le = lc; // case 2S, Le=0 means 256
                return out;
            }
            // 0x00 followed by data that is not valid extended length: suspicious.
            out.lengthSuspicious = true;
            out.lengthNote = "Lc=0 with " + (rest - 1) + " trailing bytes is not valid extended length";
            out.data = Arrays.copyOfRange(apdu, 5, apdu.length);
            return out;
        }
        if (rest == 1) {
            out.le = lc; // case 2S
            return out;
        }
        // case 3S / 4S
        if (lc > rest - 1) {
            out.lengthSuspicious = true;
            out.lengthNote = "short Lc=" + lc + " exceeds remaining " + (rest - 1) + " bytes";
            out.data = Arrays.copyOfRange(apdu, 5, apdu.length);
            flagAbsurdLength(out, lc, apdu.length);
            return out;
        }
        out.data = Arrays.copyOfRange(apdu, 5, 5 + lc);
        flagAbsurdLength(out, lc, apdu.length);
        int after = 5 + lc;
        if (apdu.length == after + 1) {
            out.le = apdu[after] & 0xFF;
        } else if (apdu.length > after + 1) {
            out.lengthSuspicious = true;
            out.lengthNote = out.lengthNote.isEmpty()
                    ? "trailing bytes after data+Le"
                    : out.lengthNote + "; trailing bytes after data+Le";
        }
        return out;
    }

    /** Length-logging mode: flag absurd Lc values so malformed readers stand out in logs. */
    private static void flagAbsurdLength(ParsedApdu out, int lc, int apduLength) {
        if (lc > 65535 || lc > apduLength * 4 + 256 || (lc > 256 && !out.extendedLength)) {
            out.lengthSuspicious = true;
            String note = "absurd Lc=" + lc + " for APDU length " + apduLength;
            out.lengthNote = out.lengthNote.isEmpty() ? note : out.lengthNote + "; " + note;
        }
    }

    public static byte[] hexBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static String hex(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            result.append(Character.forDigit((b >> 4) & 0xF, 16));
            result.append(Character.forDigit(b & 0xF, 16));
        }
        return result.toString();
    }

    /** Prefix match without Android dependencies (mirrors Utils.arrayBeginsWith). */
    public static boolean beginsWith(byte[] fullArray, byte[] prefix) {
        if (fullArray == null || prefix == null) {
            return false;
        }
        if (prefix.length == 0 || fullArray.length < prefix.length) {
            return false;
        }
        return Arrays.equals(Arrays.copyOf(fullArray, prefix.length), prefix);
    }

    /** SELECT response router: PPSE DF name vs known AIDs (improvement 4). */
    public static String routeSelect(byte[] selectData) {
        if (selectData == null) {
            return "unknown";
        }
        String hex = hex(selectData).toUpperCase();
        if (hex.equals(PPSE_DF_NAME)) {
            return "ppse";
        }
        if (hex.startsWith(AID_VISA)) {
            return "visa";
        }
        if (hex.startsWith(AID_MASTERCARD)) {
            return "mastercard";
        }
        if (hex.startsWith(AID_AMEX)) {
            return "amex";
        }
        if (hex.startsWith(AID_DISCOVER)) {
            return "discover";
        }
        return "unknown";
    }

    // ------------------------------------------------------------------
    // Dynamic GPO (improvement 2)
    // ------------------------------------------------------------------

    /** Mutable per-tap session state: ATC increments, UN is echoed, reset on deactivate. */
    public static final class SessionState {
        public int atc;
        public byte[] lastUnpredictableNumber = new byte[0];
        public byte[] pendingChainedResponse; // bytes still to deliver via GET RESPONSE (61xx)
        /** Raw PDOL bytes (tag+length list from SELECT 9F38) captured at SELECT time. */
        public byte[] activePdol;
        /** Raw AFL bytes (tag 94 from the GPO template) captured at GPO time. */
        public byte[] activeAfl;
        /** CDOL1 bytes collected from READ RECORD data (tag 8C). */
        public byte[] activeCdol1;
        /** CDOL2 bytes collected from READ RECORD data (tag 8D). */
        public byte[] activeCdol2;
        /** GENERATE AC calls seen this tap (drives 1st vs 2nd AC template selection). */
        public int generateAcCount;

        public SessionState(int initialAtc) {
            this.atc = initialAtc & 0xFFFF;
        }

        public void reset(int initialAtc) {
            this.atc = initialAtc & 0xFFFF;
            this.lastUnpredictableNumber = new byte[0];
            this.pendingChainedResponse = null;
            this.activePdol = null;
            this.activeAfl = null;
            this.activeCdol1 = null;
            this.activeCdol2 = null;
            this.generateAcCount = 0;
        }
    }

    /**
     * Extract tag 9F37 (unpredictable number) from the GPO PDOL-related data field.
     * Returns empty array when absent (e.g. Mastercard null-PDOL path).
     *
     * <p>When the session carries the real PDOL (tag+length list from SELECT 9F38),
     * the UN is located by walking the PDOL field-by-field instead of assuming a
     * fixed layout; otherwise the legacy trailing-4-bytes heuristic applies.
     */
    public static byte[] extractUnpredictableNumber(byte[] gpoData) {
        return extractUnpredictableNumber(gpoData, null);
    }

    public static byte[] extractUnpredictableNumber(byte[] gpoData, byte[] pdol) {
        if (gpoData == null || gpoData.length == 0) {
            return new byte[0];
        }
        // Two PDOL encodings occur in the wild:
        //  - constructed "83 <len> <pdol values>"
        //  - raw PDOL values (Mastercard path / some readers send the values bare)
        byte[] values = gpoData;
        if (gpoData.length >= 2 && (gpoData[0] & 0xFF) == 0x83) {
            int len = gpoData[1] & 0xFF;
            int start = 2;
            if (len > gpoData.length - start) {
                len = gpoData.length - start;
            }
            values = Arrays.copyOfRange(gpoData, start, start + len);
        }
        if (pdol != null && pdol.length > 0) {
            byte[] located = locatePdolField(values, pdol, 0x9F37);
            if (located != null) {
                return located;
            }
            // PDOL known but carries no UN (e.g. null-PDOL path): no echo.
            return new byte[0];
        }
        // Legacy fallback (no PDOL captured): the Visa PDOL in this repo ends with
        // 9F37 (4 bytes) as the last field:
        // 9F66(4) 9F02(6) 9F03(6) 9F1A(2) 95(5) 5F2A(2) 9A(3) 9C(1) 9F37(4).
        int expectedPdolLength = 4 + 6 + 6 + 2 + 5 + 2 + 3 + 1 + 4; // 33
        if (values.length == expectedPdolLength) {
            return Arrays.copyOfRange(values, values.length - 4, values.length);
        }
        if (values.length >= 4) {
            // Best effort: echo the trailing 4 bytes (most PDOLs end with UN).
            return Arrays.copyOfRange(values, values.length - 4, values.length);
        }
        return new byte[0];
    }

    /**
     * Slice one field out of PDOL values using the PDOL tag+length list.
     * Returns null when the tag is absent or the values are shorter than declared.
     */
    public static byte[] locatePdolField(byte[] values, byte[] pdol, int wantedTag) {
        int offset = 0;
        int pos = 0;
        while (pos < pdol.length) {
            int[] tag = readTag(pdol, pos);
            if (tag == null) {
                return null;
            }
            pos = tag[1];
            if (pos >= pdol.length) {
                return null;
            }
            int fieldLen = pdol[pos++] & 0xFF;
            if (tag[0] == wantedTag) {
                if (offset + fieldLen > values.length) {
                    return null;
                }
                return Arrays.copyOfRange(values, offset, offset + fieldLen);
            }
            offset += fieldLen;
        }
        return null;
    }

    /** Total PDOL values length (sum of field lengths); -1 when malformed. */
    public static int pdolValuesLength(byte[] pdol) {
        if (pdol == null) {
            return -1;
        }
        int total = 0;
        int pos = 0;
        while (pos < pdol.length) {
            int[] tag = readTag(pdol, pos);
            if (tag == null) {
                return -1;
            }
            pos = tag[1];
            if (pos >= pdol.length) {
                return -1;
            }
            total += pdol[pos++] & 0xFF;
        }
        return total;
    }

    /** Read a BER tag at offset; returns {tag, nextOffset} or null. */
    private static int[] readTag(byte[] buffer, int offset) {
        if (offset >= buffer.length) {
            return null;
        }
        int t = buffer[offset++] & 0xFF;
        if ((t & 0x1F) == 0x1F) {
            do {
                if (offset >= buffer.length) {
                    return null;
                }
                int b = buffer[offset++] & 0xFF;
                t = (t << 8) | b;
                if ((b & 0x80) == 0) {
                    break;
                }
            } while (true);
        }
        return new int[]{t, offset};
    }

    /**
     * Parse an AFL (tag 94 value) into {sfi, firstRecord, lastRecord, offlineAuthRecords}
     * quadruples. Trailing incomplete bytes are ignored.
     */
    public static int[][] parseAfl(byte[] afl) {
        if (afl == null || afl.length < 4) {
            return new int[0][];
        }
        int entries = afl.length / 4;
        int[][] out = new int[entries][];
        for (int i = 0; i < entries; i++) {
            int o = i * 4;
            out[i] = new int[]{
                    (afl[o] & 0xFF) >> 3,
                    afl[o + 1] & 0xFF,
                    afl[o + 2] & 0xFF,
                    afl[o + 3] & 0xFF};
        }
        return out;
    }

    /**
     * GENERATE AC cryptogram type from the P1 reference-control byte:
     * bit 7 set = TC (online-completed), bit 6 set = ARQC (online), else AAC (decline).
     * Returns "AAC"/"TC"/"ARQC". Pure decode helper for log lines.
     */
    public static String acTypeFromP1(byte p1) {
        int v = p1 & 0xFF;
        if ((v & 0x80) != 0) {
            return "TC";
        }
        if ((v & 0x40) != 0) {
            return "ARQC";
        }
        return "AAC";
    }

    /**
     * True when (sfi, record) falls inside any AFL-advertised range.
     * Used by the strict AFL enforcement mode in the service layer.
     */
    public static boolean isAflListed(byte[] afl, int sfi, int record) {
        int[][] entries = parseAfl(afl);
        for (int[] e : entries) {
            if (e[0] == sfi && record >= e[1] && record <= e[2]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Find a TLV value by tag anywhere nested in the buffer (any length).
     * Returns null when absent or malformed.
     */
    public static byte[] findTlv(byte[] buffer, int tag) {
        int start = 0;
        if (buffer != null && buffer.length >= 2 && (buffer[0] == (byte) 0x77
                || buffer[0] == (byte) 0x80 || buffer[0] == (byte) 0x70
                || buffer[0] == (byte) 0x6F)) {
            int[] outer = readLength(buffer, 1);
            if (outer == null) {
                return null;
            }
            start = outer[1];
        }
        return findTlvAt(buffer, start, buffer.length, tag);
    }

    private static byte[] findTlvAt(byte[] buffer, int pos, int end, int tag) {
        while (buffer != null && pos + 2 <= end) {
            int tagStart = pos;
            int[] t = readTag(buffer, pos);
            if (t == null) {
                return null;
            }
            int valueLenPos = t[1];
            int[] len = readLength(buffer, valueLenPos);
            if (len == null || len[0] < 0 || len[1] + len[0] > end) {
                return null;
            }
            if (t[0] == tag) {
                return Arrays.copyOfRange(buffer, len[1], len[1] + len[0]);
            }
            boolean constructed = (buffer[tagStart] & 0x20) != 0
                    && t[0] != 0x50 && t[0] != 0x5A && t[0] != 0x57
                    && t[0] != 0x56 && t[0] != 0x9F12;
            if (constructed) {
                byte[] nested = findTlvAt(buffer, len[1], len[1] + len[0], tag);
                if (nested != null) {
                    return nested;
                }
            }
            pos = len[1] + len[0];
        }
        return null;
    }

    /**
     * Build the GPO response template (tag 77 or 80, without SW) with the terminal's
     * UN echoed back and the session ATC incremented. Byte positions of the patched
     * fields are derived by TLV lookup, not hard-coded offsets.
     *
     * @param gpoTemplate static recorded GPO template (tag 77/80 TLV, no SW)
     * @param gpoData     GPO command data field (PDOL values)
     * @param state       mutable session state (ATC incremented in place)
     * @param cvc3ByAtc   optional ATC -&gt; CVC3 dictionary patch (may be null)
     * @return patched GPO template bytes (no SW)
     */
    public static byte[] buildDynamicGpoResponse(byte[] gpoTemplate, byte[] gpoData,
            SessionState state, java.util.Map<Integer, byte[]> cvc3ByAtc) {
        byte[] out = Arrays.copyOf(gpoTemplate, gpoTemplate.length);
        byte[] un = extractUnpredictableNumber(gpoData, state.activePdol);
        state.lastUnpredictableNumber = un;
        state.atc = (state.atc + 1) & 0xFFFF;
        if (un.length > 0) {
            patchTlv(out, 0x9F26, buildUnpredictableEcho(un));
        }
        patchTlv(out, 0x9F36, new byte[]{(byte) ((state.atc >> 8) & 0xFF), (byte) (state.atc & 0xFF)});
        if (cvc3ByAtc != null && cvc3ByAtc.containsKey(state.atc)) {
            byte[] cvc3 = cvc3ByAtc.get(state.atc);
            if (cvc3 != null && cvc3.length == 2) {
                patchTlv(out, 0x9F62, cvc3);
            }
        }
        // Capture the AFL the template advertises so READ RECORD can be validated
        // against it (AFL-driven routing, roadmap near-term item).
        byte[] afl = findTlv(out, TAG_AFL);
        if (afl != null) {
            state.activeAfl = afl;
        }
        return out;
    }

    /**
     * Derive an 8-byte field from the terminal UN (padded/repeated) so the echoed
     * cryptogram input visibly tracks the reader challenge in lab traces.
     */
    private static byte[] buildUnpredictableEcho(byte[] un) {
        byte[] echo = new byte[8];
        if (un.length == 0) {
            return echo;
        }
        for (int i = 0; i < echo.length; i++) {
            echo[i] = un[i % un.length];
        }
        return echo;
    }

    /**
     * Patch the value bytes of the first TLV with the given tag in-place.
     *
     * @return true when the tag was found with a matching length
     */
    public static boolean patchTlv(byte[] buffer, int tag, byte[] newValue) {
        int pos = tlvValueOffset(buffer, tag, newValue.length);
        if (pos < 0) {
            return false;
        }
        System.arraycopy(newValue, 0, buffer, pos, newValue.length);
        return true;
    }

    /** Locate the value offset of a TLV tag whose length equals expectedLength. */
    private static int tlvValueOffset(byte[] buffer, int tag, int expectedLength) {
        int start = 0;
        if (buffer.length >= 2 && (buffer[0] == (byte) 0x77 || buffer[0] == (byte) 0x80
                || buffer[0] == (byte) 0x70 || buffer[0] == (byte) 0x6F)) {
            int[] outer = readLength(buffer, 1);
            if (outer == null) {
                return -1;
            }
            start = outer[1];
        }
        return tlvSearch(buffer, start, buffer.length, tag, expectedLength);
    }

    private static int tlvSearch(byte[] buffer, int pos, int end, int tag, int expectedLength) {
        while (pos + 2 <= end) {
            int tagStart = pos;
            int t = buffer[pos++] & 0xFF;
            if ((t & 0x1F) == 0x1F) {
                if (pos >= end) {
                    return -1;
                }
                t = (t << 8) | (buffer[pos++] & 0xFF);
                if ((t & 0x80) != 0) {
                    if (pos >= end) {
                        return -1;
                    }
                    t = (t << 8) | (buffer[pos++] & 0xFF);
                }
            }
            int[] len = readLength(buffer, pos);
            if (len == null || len[0] < 0 || pos + (len[1] - pos) + len[0] > end) {
                return -1;
            }
            int valueOffset = len[1];
            int valueEnd = valueOffset + len[0];
            if (t == tag && len[0] == expectedLength) {
                return valueOffset;
            }
            boolean constructed = (buffer[tagStart] & 0x20) != 0
                    && t != 0x50 && t != 0x5A && t != 0x57 && t != 0x56 && t != 0x9F12;
            if (constructed) {
                int nested = tlvSearch(buffer, valueOffset, valueEnd, tag, expectedLength);
                if (nested >= 0) {
                    return nested;
                }
            }
            pos = valueEnd;
        }
        return -1;
    }

    /** Read a TLV length at offset; returns {length, firstValueOffset} or null. */
    private static int[] readLength(byte[] buffer, int offset) {
        if (offset >= buffer.length) {
            return null;
        }
        int first = buffer[offset++] & 0xFF;
        if (first < 0x80) {
            return new int[]{first, offset};
        }
        int bytes = first & 0x7F;
        if (bytes < 1 || bytes > 2 || offset + bytes > buffer.length) {
            return null;
        }
        int len = 0;
        for (int i = 0; i < bytes; i++) {
            len = (len << 8) | (buffer[offset++] & 0xFF);
        }
        return new int[]{len, offset};
    }

    // ------------------------------------------------------------------
    // 61xx / GET RESPONSE chaining (improvement 5)
    // ------------------------------------------------------------------

    /** Split a response into first chunk + remainder for 61xx chaining. */
    public static byte[][] chainResponse(byte[] fullResponseWithoutSw, int maxFirstChunk) {
        if (fullResponseWithoutSw == null) {
            return new byte[][]{new byte[0], null};
        }
        if (fullResponseWithoutSw.length <= maxFirstChunk) {
            return new byte[][]{fullResponseWithoutSw, null};
        }
        return new byte[][]{
                Arrays.copyOfRange(fullResponseWithoutSw, 0, maxFirstChunk),
                Arrays.copyOfRange(fullResponseWithoutSw, maxFirstChunk, fullResponseWithoutSw.length)};
    }

    public static byte[] statusRemaining(int remaining) {
        return new byte[]{(byte) 0x61, (byte) (remaining & 0xFF)};
    }

    public static byte[] concat(byte[] a, byte[] b) {
        if (a == null) {
            return b == null ? new byte[0] : Arrays.copyOf(b, b.length);
        }
        if (b == null) {
            return Arrays.copyOf(a, a.length);
        }
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}

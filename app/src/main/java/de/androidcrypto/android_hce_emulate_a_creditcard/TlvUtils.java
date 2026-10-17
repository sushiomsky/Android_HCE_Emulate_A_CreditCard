package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Minimal BER-TLV reader for EMV responses (cf. Crash &amp; Pay, Appendix B).
 * Multi-byte tags, short- and long-form lengths, one recursion into constructed
 * tags (bit 6 set, e.g. 0x70, 0x77, 0x6F). Malformed input stops the parse
 * instead of throwing, so it is safe to run on arbitrary reader responses.
 */
public final class TlvUtils {

    private static final int MAX_DEPTH = 4;
    private static final int MAX_ITEMS = 64;

    private TlvUtils() {
    }

    /** One parsed tag-length-value triple. */
    public static class Tlv {
        public final String tag;
        public final byte[] value;
        public final boolean constructed;
        public final List<Tlv> children = new ArrayList<>();

        Tlv(String tag, byte[] value, boolean constructed) {
            this.tag = tag;
            this.value = value;
            this.constructed = constructed;
        }
    }

    /** Parses top-level TLVs from hex; never throws. */
    public static List<Tlv> parse(String hex) {
        List<Tlv> out = new ArrayList<>();
        if (hex == null) return out;
        try {
            byte[] data = Utils.hexStringToByteArray(hex.toLowerCase(Locale.US));
            parseInto(data, 0, data.length, out, 0);
        } catch (Exception ignored) {
        }
        return out;
    }

    /** Compact one-line summary, e.g. {@code 77[198]{82[2] 57[19] 9F36[2]}}. */
    public static String summarize(String hex) {
        List<Tlv> tlvs = parse(hex);
        if (tlvs.isEmpty()) return "not TLV";
        StringBuilder sb = new StringBuilder();
        summarizeInto(tlvs, sb, 0);
        return sb.toString();
    }

    private static void summarizeInto(List<Tlv> tlvs, StringBuilder sb, int depth) {
        boolean first = true;
        for (Tlv t : tlvs) {
            if (!first) sb.append(' ');
            first = false;
            sb.append(t.tag).append('[').append(t.value.length).append(']');
            if (!t.children.isEmpty() && depth < MAX_DEPTH) {
                sb.append('{');
                summarizeInto(t.children, sb, depth + 1);
                sb.append('}');
            }
        }
    }

    private static void parseInto(byte[] data, int off, int end, List<Tlv> out, int depth) {
        while (off < end && out.size() < MAX_ITEMS) {
            int tagStart = off;
            int b = data[off++] & 0xFF;
            boolean constructed = (b & 0x20) != 0;
            if ((b & 0x1F) == 0x1F) { // multi-byte tag
                do {
                    if (off >= end) return;
                    b = data[off++] & 0xFF;
                } while ((b & 0x80) != 0);
            }
            String tag = Utils.bytesToHexNpe(copyOf(data, tagStart, off));
            if (off >= end) return;
            int lb = data[off++] & 0xFF;
            int len;
            if ((lb & 0x80) == 0) {
                len = lb;
            } else { // long form: lower 7 bits = number of length bytes
                int nLen = lb & 0x7F;
                if (nLen == 0 || nLen > 4 || off + nLen > end) return;
                len = 0;
                for (int i = 0; i < nLen; i++) len = (len << 8) | (data[off++] & 0xFF);
            }
            if (len < 0 || off + len > end) return;
            byte[] value = copyOf(data, off, off + len);
            off += len;
            Tlv t = new Tlv(tag, value, constructed);
            out.add(t);
            if (constructed && depth < MAX_DEPTH && value.length >= 2) {
                parseInto(value, 0, value.length, t.children, depth + 1);
            }
        }
    }

    private static byte[] copyOf(byte[] data, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(data, from, out, 0, out.length);
        return out;
    }
}

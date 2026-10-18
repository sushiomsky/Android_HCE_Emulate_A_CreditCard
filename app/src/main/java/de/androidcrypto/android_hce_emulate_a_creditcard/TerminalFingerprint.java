package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Terminal fingerprinting from GPO PDOL data.
 *
 * <p>The card is passive, but the terminal volunteers identifying bytes inside
 * the GPO command: IFD serial number (9F1E), terminal ID (9F1C), terminal type
 * (9F35), capabilities (9F33/9F40), TTQ (9F66) and country (9F1A). Walking the
 * SELECT-GPO PDOL contract (tag+length pairs) over the raw values maps each
 * value back to its tag. The fingerprint is informational only — many terminals
 * send zeros or model-wide constants, so it distinguishes configurations, not
 * necessarily individual devices.</p>
 */
public final class TerminalFingerprint {

    /** PDOL tags treated as terminal-identifying (value bytes join the fingerprint). */
    private static final String[] FP_TAGS = {
            "9F1E", "9F1C", "9F35", "9F33", "9F40", "9F66", "9F1A", "5F2A"
    };

    private TerminalFingerprint() {
    }

    /** Result, or null when the PDOL contract/values are unusable. */
    public static class Fingerprint {
        public final Map<String, String> fields = new LinkedHashMap<>();
        public final String id;

        Fingerprint(Map<String, String> fields) {
            this.fields.putAll(fields);
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> e : fields.entrySet()) {
                sb.append(e.getKey()).append('=').append(e.getValue()).append(';');
            }
            this.id = String.format(Locale.US, "%08X", sb.toString().hashCode());
        }

        @Override
        public String toString() {
            List<String> parts = new ArrayList<>();
            for (Map.Entry<String, String> e : fields.entrySet()) {
                parts.add(e.getKey() + "=" + e.getValue());
            }
            return "[" + id + "] " + join(parts, " ");
        }

        private static String join(List<String> parts, String sep) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parts.size(); i++) {
                if (i > 0) sb.append(sep);
                sb.append(parts.get(i));
            }
            return sb.toString();
        }
    }

    /**
     * @param pdolTemplate PDOL contract bytes (tag+len pairs, e.g. from SELECT 9F38)
     * @param values       raw PDOL values, with or without the 83 wrapper
     */
    public static Fingerprint summarize(byte[] pdolTemplate, byte[] values) {
        if (pdolTemplate == null || values == null) return null;
        byte[] v = stripWrapper(values);
        try {
            Map<String, String> all = walk(pdolTemplate, v);
            Map<String, String> fp = new LinkedHashMap<>();
            for (String tag : FP_TAGS) {
                if (all.containsKey(tag)) fp.put(tag, all.get(tag));
            }
            if (fp.isEmpty()) return null;
            return new Fingerprint(fp);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] stripWrapper(byte[] values) {
        if (values.length >= 2 && (values[0] & 0xFF) == 0x83) {
            int len = values[1] & 0xFF;
            int start = 2;
            if (len > values.length - start) len = values.length - start;
            byte[] copy = new byte[len];
            System.arraycopy(values, start, copy, 0, len);
            return copy;
        }
        return values;
    }

    /** Walks tag/len pairs of the template over the value bytes. */
    private static Map<String, String> walk(byte[] template, byte[] values) {
        Map<String, String> out = new LinkedHashMap<>();
        int t = 0, v = 0;
        while (t < template.length) {
            int tagStart = t;
            int b = template[t++] & 0xFF;
            if ((b & 0x1F) == 0x1F) {
                if (t >= template.length) break;
                t++; // two-byte tag (all EMV PDOL tags are at most 2 bytes)
            }
            if (t >= template.length) break;
            int len = template[t++] & 0xFF;
            if ((len & 0x80) != 0) break; // long form never appears in PDOL contracts
            String tag = Utils.bytesToHexNpe(copyOf(template, tagStart, t - 1)).toUpperCase(Locale.US);
            if (v + len > values.length) break;
            out.put(tag, Utils.bytesToHexNpe(copyOf(values, v, v + len)).toUpperCase(Locale.US));
            v += len;
        }
        return out;
    }

    private static byte[] copyOf(byte[] data, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(data, from, out, 0, out.length);
        return out;
    }
}

package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.ArrayList;
import java.util.List;

/**
 * Malformed-response probes for reader length-handling verification
 * (cf. Contactless Overflow: readers that trust the declared {@code 82 XX XX}
 * length field without checking what was actually received).
 *
 * <p>Each case is a fixed response body (status word {@code 9000} is appended
 * by the service). {@code declared} is what the length field claims,
 * {@code actual} what is really sent:</p>
 */
public final class LabProbe {

    public static class Case {
        public final String name;
        public final byte[] body;
        public final int declared;
        public final int actual;

        Case(String name, byte[] body, int declared, int actual) {
            this.name = name;
            this.body = body;
            this.declared = declared;
            this.actual = actual;
        }
    }

    private LabProbe() {
    }

    public static List<Case> cases() {
        List<Case> out = new ArrayList<>();
        out.add(new Case("baseline-41-fill", fill(0x41, 512), 512, 512));
        // declares 64KB, sends 512B — reader must not read past what arrived
        out.add(new Case("declare-64k-send-512", concat(
                Utils.hexStringToByteArray("7782FFFF"), fill(0x41, 508)), 0xFFFF, 512));
        // exact 0x138 boundary from the paper, well-formed
        out.add(new Case("declare-0x138-exact", concat(
                Utils.hexStringToByteArray("77820138"), fill(0x41, 0x138)), 0x138, 0x138 + 4));
        // one byte over the paper's threshold, well-formed
        out.add(new Case("declare-0x139-exact", concat(
                Utils.hexStringToByteArray("77820139"), fill(0x41, 0x139)), 0x139, 0x139 + 4));
        // declares 0x2000, sends 256B payload
        out.add(new Case("declare-8k-send-256", concat(
                Utils.hexStringToByteArray("77822000"), fill(0x41, 252)), 0x2000, 256));
        // nested: inner length (0xB0) exceeds available bytes
        out.add(new Case("nested-inner-overflow", concat(
                Utils.hexStringToByteArray("700E9F4681B0"), fill(0x42, 12)), 0xB0, 18));
        // 3-byte long form (0x83) declares 64KB, sends 65B
        out.add(new Case("longform-83-declare-64k", concat(
                Utils.hexStringToByteArray("7083010000"), fill(0x43, 60)), 0x10000, 65));
        // declares 512B, sends nothing after the header
        out.add(new Case("declare-512-send-0",
                Utils.hexStringToByteArray("77820200"), 512, 4));
        return out;
    }

    private static byte[] fill(int b, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) out[i] = (byte) b;
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        return Utils.concatenateByteArrays(a, b);
    }
}

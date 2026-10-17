package de.androidcrypto.android_hce_emulate_a_creditcard;

/**
 * Builds oversized APDU response bodies for contactless reader robustness testing
 * in the lab (devices you own / are authorized to test).
 *
 * <p>Background: public research ("Contactless Overflow", IOActive 2023) showed NFC
 * payment readers with stack buffer overflows reachable via extended-length APDU
 * responses (length encoded {@code 82 XX XX}, up to 0xFFFF bytes). A phone doing
 * Host Card Emulation can deliver such responses where USB readers (ACR122U,
 * capped at 0xFF) cannot. Vendors were notified and shipped fixes; this helper
 * exists so you can verify <em>your own</em> lab readers handle long responses
 * gracefully instead of crashing.</p>
 */
public final class LabPayload {

    /** Hard cap for a response body (max extended-APDU length). */
    public static final int MAX_LEN = 0xFFFF;

    /** Lengths (response body bytes) stepped through on successive taps in auto-sweep mode. */
    public static final int[] SWEEP_LENGTHS = {256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65535};

    private LabPayload() {
    }

    /**
     * @param bodyLen  response body length in bytes, 0..{@link #MAX_LEN}
     * @param pattern  fill bytes, repeated cyclically (non-empty)
     * @return bodyLen bytes of cyclic pattern
     * @throws IllegalArgumentException on out-of-range length or empty pattern
     */
    public static byte[] buildResponse(int bodyLen, byte[] pattern) {
        if (bodyLen < 0 || bodyLen > MAX_LEN) {
            throw new IllegalArgumentException("bodyLen out of range: " + bodyLen);
        }
        if (pattern == null || pattern.length == 0) {
            throw new IllegalArgumentException("pattern must not be empty");
        }
        byte[] out = new byte[bodyLen];
        for (int i = 0; i < bodyLen; i++) {
            out[i] = pattern[i % pattern.length];
        }
        return out;
    }
}

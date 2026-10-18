package de.androidcrypto.android_hce_emulate_a_creditcard;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Local unit tests for {@link TerminalFingerprint}.
 */
public class TerminalFingerprintTest {

    // Visa-style PDOL: 9F66(4) 9F02(6) 9F03(6) 9F1A(2) 95(5) 5F2A(2) 9A(3) 9C(1) 9F37(4)
    private static final String PDOL = "9F66049F02069F03069F1A0295055F2A029A039C019F3704";
    // matching 33B values with IFD serial + terminal ID + type + caps filled
    private static final String VALUES =
            "27000000" + "000000001000" + "000000000000" + "0978" + "0000000000"
                    + "0978" + "230301" + "00" + "38393031";

    @Test
    public void extractsTerminalFields() {
        TerminalFingerprint.Fingerprint fp = TerminalFingerprint.summarize(
                Utils.hexStringToByteArray(PDOL), Utils.hexStringToByteArray("83" + "21" + VALUES));
        assertNotNull(fp);
        assertEquals("0978", fp.fields.get("9F1A"));
        assertEquals("27000000", fp.fields.get("9F66"));
        assertTrue(fp.id.matches("[0-9A-F]{8}"));
    }

    @Test
    public void skipsNonIdentifyingTags() {
        TerminalFingerprint.Fingerprint fp = TerminalFingerprint.summarize(
                Utils.hexStringToByteArray(PDOL), Utils.hexStringToByteArray(VALUES));
        assertNotNull(fp);
        assertFalse(fp.fields.containsKey("9F02")); // amount, not identifying
        assertFalse(fp.fields.containsKey("9F37")); // unpredictable number, random
    }

    @Test
    public void stableIdForSameInput() {
        byte[] pdol = Utils.hexStringToByteArray(PDOL);
        byte[] vals = Utils.hexStringToByteArray(VALUES);
        assertEquals(TerminalFingerprint.summarize(pdol, vals).id,
                TerminalFingerprint.summarize(pdol, vals).id);
    }

    @Test
    public void nullOnGarbage() {
        assertNull(TerminalFingerprint.summarize(null, new byte[4]));
        assertNull(TerminalFingerprint.summarize(new byte[4], null));
        // PDOL with only amount/UN tags -> nothing identifying
        assertNull(TerminalFingerprint.summarize(
                Utils.hexStringToByteArray("9F02069F3704"),
                Utils.hexStringToByteArray("00000000100038393031")));
        // truncated values
        assertNull(TerminalFingerprint.summarize(
                Utils.hexStringToByteArray(PDOL), new byte[]{0x01}));
    }
}

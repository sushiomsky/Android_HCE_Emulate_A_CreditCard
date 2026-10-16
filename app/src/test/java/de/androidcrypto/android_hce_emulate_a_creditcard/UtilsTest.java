package de.androidcrypto.android_hce_emulate_a_creditcard;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Local unit tests for the pure-JVM helpers in {@link Utils}.
 * These run on the development machine (no device needed).
 */
public class UtilsTest {
    @Test
    public void hexStringToByteArray_roundTrip() {
        String hex = "00a404000e325041592e5359532e444446303100";
        assertEquals(hex, Utils.bytesToHexNpe(Utils.hexStringToByteArray(hex)));
    }

    @Test
    public void bytesToHexNpe_null_returnsEmpty() {
        assertEquals("", Utils.bytesToHexNpe(null));
    }

    @Test
    public void bytesToHexNpe_padsSingleNibbles() {
        assertEquals("000f10ff", Utils.bytesToHexNpe(new byte[]{0x00, 0x0F, 0x10, (byte) 0xFF}));
    }

    @Test
    public void concatenateByteArrays_appendsStatusWord() {
        byte[] body = Utils.hexStringToByteArray("6f2b84");
        byte[] sw = Utils.hexStringToByteArray("9000");
        assertArrayEquals(Utils.hexStringToByteArray("6f2b849000"),
                Utils.concatenateByteArrays(body, sw));
    }

    @Test
    public void arrayBeginsWith_gpoPrefix() {
        byte[] gpo = Utils.hexStringToByteArray("80a80000238321");
        byte[] prefix = Utils.hexStringToByteArray("80a8");
        assertTrue(Utils.arrayBeginsWith(gpo, prefix));
        assertFalse(Utils.arrayBeginsWith(gpo, Utils.hexStringToByteArray("00b2")));
        assertFalse(Utils.arrayBeginsWith(null, prefix));
        assertFalse(Utils.arrayBeginsWith(gpo, null));
        assertFalse(Utils.arrayBeginsWith(new byte[0], prefix));
    }
}

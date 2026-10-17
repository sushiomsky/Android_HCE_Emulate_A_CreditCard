package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.List;

/**
 * Unit tests for the pcap-style tap export format ({@link TapExport#parse} and
 * the in-memory record buffer). File IO paths ({@code exportTap}/{@code readTap})
 * need a Context and are exercised on-device; the format round-trip is pure JVM.
 */
public class TapExportTest {

    @Test
    public void recordAndParse_roundTrip() {
        TapExport.beginTap("visa");
        assertEquals(0, TapExport.pendingCount());
        TapExport.record(
                EmvCardEmulatorCore.hexBytes("00A404000E325041592E5359532E444446303100"),
                EmvCardEmulatorCore.hexBytes("6F2B840E325041592E5359532E44444630319000"));
        TapExport.record(
                EmvCardEmulatorCore.hexBytes("80CA9F3600"),
                EmvCardEmulatorCore.hexBytes("03AA9000"));
        assertEquals(2, TapExport.pendingCount());

        // Rebuild the file body the way exportTap writes it, then parse it back.
        StringBuilder sb = new StringBuilder("# HCE tap export scheme=visa pairs=2\n");
        sb.append("C:00A404000E325041592E5359532E444446303100 R:6F2B840E325041592E5359532E44444630319000\n");
        sb.append("C:80CA9F3600 R:03AA9000\n");
        sb.append("# trailing comment\n");
        sb.append("\n");
        List<TapExport.Exchange> parsed = TapExport.parse(sb.toString());
        assertEquals(2, parsed.size());
        assertArrayEquals(
                EmvCardEmulatorCore.hexBytes("00A404000E325041592E5359532E444446303100"),
                parsed.get(0).command);
        assertArrayEquals(
                EmvCardEmulatorCore.hexBytes("6F2B840E325041592E5359532E44444630319000"),
                parsed.get(0).response);
        assertArrayEquals(EmvCardEmulatorCore.hexBytes("80CA9F3600"), parsed.get(1).command);
        assertArrayEquals(EmvCardEmulatorCore.hexBytes("03AA9000"), parsed.get(1).response);
        TapExport.beginTap("visa"); // leave the buffer clean for other tests
    }

    @Test
    public void parse_skipsCommentsBlanksAndMalformed() {
        List<TapExport.Exchange> parsed = TapExport.parse(
                "# comment\n"
                        + "\n"
                        + "not an exchange line\n"
                        + "C:00C00000FF R:9000\n"
                        + "C: R:9000\n");
        assertEquals(1, parsed.size());
        assertArrayEquals(EmvCardEmulatorCore.hexBytes("00C00000FF"), parsed.get(0).command);
    }

    @Test
    public void parse_nullAndEmpty_yieldNoExchanges() {
        assertTrue(TapExport.parse(null).isEmpty());
        assertTrue(TapExport.parse("").isEmpty());
        assertTrue(TapExport.parse("# only comments\n").isEmpty());
    }

    @Test
    public void beginTap_resetsBuffer() {
        TapExport.beginTap("mastercard");
        TapExport.record(new byte[]{0x00}, new byte[]{(byte) 0x90, 0x00});
        assertEquals(1, TapExport.pendingCount());
        TapExport.beginTap("mastercard");
        assertEquals(0, TapExport.pendingCount());
    }
}

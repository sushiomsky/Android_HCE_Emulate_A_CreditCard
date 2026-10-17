package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Loopback harness for the EMV core (improvement 7).
 *
 * <p>Runs on the JVM without Android: compile with
 * {@code javac} against the {@code app/src/main/java} sources that have no
 * Android imports (EmvCardEmulatorCore), or run the full suite with
 * {@code ./gradlew :app:testDebugUnitTest}. Each test feeds a Command APDU
 * through the same parser/dispatch the HCE services use and asserts the
 * Response APDU shape - the same conversation the "Talk to Your Credit Card"
 * reader app (https://github.com/AndroidCrypto/TalkToYourCreditCardG8) would
 * drive over NFC, replayed here as a byte loopback.
 */
public class EmvLoopbackHarnessTest {

    private static byte[] hex(String s) {
        return EmvCardEmulatorCore.hexBytes(s);
    }

    private static String hexStr(byte[] b) {
        return EmvCardEmulatorCore.hex(b);
    }

    // (1) Parser dispatches on CLA/INS/P1/P2/Lc, not byte-exact match.
    @Test
    public void parseSelectPpse_fields() {
        EmvCardEmulatorCore.ParsedApdu apdu =
                EmvCardEmulatorCore.parse(hex("00A404000E325041592E5359532E444446303100"));
        assertEquals((byte) 0x00, apdu.cla);
        assertEquals((byte) 0xA4, apdu.ins);
        assertEquals((byte) 0x04, apdu.p1);
        assertEquals((byte) 0x00, apdu.p2);
        assertEquals(14, apdu.data.length);
        assertEquals("ppse", EmvCardEmulatorCore.routeSelect(apdu.data));
    }

    @Test
    public void parseSelectAid_routingPerAid() {
        assertEquals("visa", EmvCardEmulatorCore.routeSelect(hex("A0000000031010")));
        assertEquals("mastercard", EmvCardEmulatorCore.routeSelect(hex("A0000000041010")));
        assertEquals("amex", EmvCardEmulatorCore.routeSelect(hex("A000000025")));
        assertEquals("discover", EmvCardEmulatorCore.routeSelect(hex("A000000152")));
        assertEquals("unknown", EmvCardEmulatorCore.routeSelect(hex("A0000000032010")));
    }

    @Test
    public void parseGpo_case4ShortLc() {
        // GPO from the Visa reader log: 80 A8 00 00 Lc=02 data=83 00 Le=00.
        EmvCardEmulatorCore.ParsedApdu apdu =
                EmvCardEmulatorCore.parse(hex("80A8000002830000"));
        assertEquals((byte) 0x80, apdu.cla);
        assertEquals((byte) 0xA8, apdu.ins);
        assertArrayEquals(hex("8300"), apdu.data);
        assertEquals(0, apdu.le);
    }

    // (5) Extended-length APDU + absurd-Lc flagging.
    @Test
    public void parseExtendedLength_accepts() {
        byte[] data = new byte[300];
        Arrays.fill(data, (byte) 0x11);
        byte[] apdu = new byte[4 + 3 + data.length + 2];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xA8;
        apdu[4] = 0x00;
        apdu[5] = 0x01;
        apdu[6] = (byte) 0x2C; // Lc = 300
        System.arraycopy(data, 0, apdu, 7, data.length);
        EmvCardEmulatorCore.ParsedApdu parsed = EmvCardEmulatorCore.parse(apdu);
        assertTrue(parsed.extendedLength);
        assertEquals(300, parsed.data.length);
    }

    @Test
    public void parseAbsurdShortLc_flagged() {
        // Lc claims 250 data bytes but only 3 follow.
        EmvCardEmulatorCore.ParsedApdu apdu =
                EmvCardEmulatorCore.parse(hex("80A80000FA010203"));
        assertTrue(apdu.lengthSuspicious);
        assertTrue(apdu.lengthNote.contains("Lc=250"));
    }

    // (2) Dynamic GPO: UN echo + ATC increment per tap.
    @Test
    public void gpoDynamic_unEchoAndAtcIncrement() {
        byte[] template = hex("7781C682022000940410030600"
                + "57134111111111111111D25022013650000000000F"
                + "9F100706040A03A02000"
                + "9F26089FFE5B7EE3737617"
                + "9F270180"
                + "9F360203AA"
                + "9F6C021600");
        // PDOL values ending in UN = 38393031 (from the reader log).
        byte[] gpoData = hex("8321270000000000000010000000000000000978000000000009782303010038393031");
        EmvCardEmulatorCore.SessionState state = new EmvCardEmulatorCore.SessionState(0x03AA);
        byte[] r1 = EmvCardEmulatorCore.buildDynamicGpoResponse(template, gpoData, state, null);
        assertEquals(0x03AB, state.atc);
        assertArrayEquals(hex("38393031"), state.lastUnpredictableNumber);
        // ATC bytes patched to 03 AB.
        assertTrue(hexStr(r1).toLowerCase().contains("9f360203ab"));
        // UN echoed into 9F26 (repeated 38393031).
        assertTrue(hexStr(r1).toLowerCase().contains("9f26083839303138393031"));
        byte[] r2 = EmvCardEmulatorCore.buildDynamicGpoResponse(template, gpoData, state, null);
        assertEquals(0x03AC, state.atc);
        assertTrue(hexStr(r2).toLowerCase().contains("9f360203ac"));
    }

    @Test
    public void gpoDynamic_cvc3DictionaryPatch() {
        byte[] template = hex("770C9F360202019F620200009F6C020100");
        Map<Integer, byte[]> cvc3 = new HashMap<Integer, byte[]>();
        cvc3.put(0x0002, new byte[]{(byte) 0xAB, (byte) 0xCD});
        EmvCardEmulatorCore.SessionState state = new EmvCardEmulatorCore.SessionState(0x0001);
        byte[] out = EmvCardEmulatorCore.buildDynamicGpoResponse(
                template, new byte[0], state, cvc3);
        assertEquals(0x0002, state.atc);
        assertTrue(hexStr(out).toLowerCase().contains("9f6202abcd"));
    }

    // (5) 61xx chaining round-trip.
    @Test
    public void chaining_splitAndStatus() {
        byte[] full = new byte[300];
        Arrays.fill(full, (byte) 0x71);
        byte[][] chained = EmvCardEmulatorCore.chainResponse(full, 255);
        assertEquals(255, chained[0].length);
        assertNotNull(chained[1]);
        assertEquals(45, chained[1].length);
        assertArrayEquals(new byte[]{(byte) 0x61, (byte) 45},
                EmvCardEmulatorCore.statusRemaining(chained[1].length));
        byte[][] tail = EmvCardEmulatorCore.chainResponse(chained[1], 255);
        assertEquals(45, tail[0].length);
        assertEquals(null, tail[1]);
    }

    // (6) arrayBeginsWith used everywhere: spot-check GPO prefix dispatch.
    @Test
    public void prefixMatch_gpoHeader() {
        assertTrue(Utils.arrayBeginsWith(
                hex("80A8000002830000"), hex("80A8")));
    }

    // TalkToYourCreditCard conversation shape: SELECT PPSE -> SELECT AID ->
    // GPO -> READ RECORD all route through the same parser without byte-exact replay.
    @Test
    public void readerConversation_allInstructionsParse() {
        String[] capdus = {
                "00A404000E325041592E5359532E444446303100",
                "00A4040007A000000003101000",
                "80A8000002830000",
                "00B2031400",
                "80AE00002D000000000000000100000000000000097800000000000978230301003839303100",
                "80CA9F3600",
                "00C00000FF",
                "802A8E80040000000000",
        };
        byte[] expectedIns = {(byte) 0xA4, (byte) 0xA4, (byte) 0xA8,
                (byte) 0xB2, (byte) 0xAE, (byte) 0xCA, (byte) 0xC0, (byte) 0x2A};
        for (int i = 0; i < capdus.length; i++) {
            EmvCardEmulatorCore.ParsedApdu apdu =
                    EmvCardEmulatorCore.parse(hex(capdus[i]));
            assertEquals("C-APDU " + capdus[i], expectedIns[i], apdu.ins);
        }
    }

    // PDOL-driven GPO: UN located field-by-field from the real SELECT PDOL.
    @Test
    public void pdolDriven_unLocatedByPdol() {
        // PDOL: amount(6) + UN(4) + date(3); UN sits in the middle, not at the end.
        byte[] pdol = hex("9F02069F37049A03");
        byte[] values = hex("000000001000AABBCCDD230301");
        assertArrayEquals(hex("AABBCCDD"),
                EmvCardEmulatorCore.extractUnpredictableNumber(values, pdol));
        assertEquals(13, EmvCardEmulatorCore.pdolValuesLength(pdol));
        // PDOL without UN -> no echo (strict, no trailing-bytes guess).
        assertEquals(0, EmvCardEmulatorCore.extractUnpredictableNumber(
                hex("000000001000230301"), hex("9F02069A03")).length);
    }

    // AFL parsing: SFI/record ranges from tag 94.
    @Test
    public void afl_parseRanges() {
        // AFL: two entries, SFI 10 rec 3-6 and SFI 10 rec 1-2 (0x50 = 10 << 3).
        int[][] entries = EmvCardEmulatorCore.parseAfl(hex("5003060050010200"));
        assertEquals(2, entries.length);
        assertEquals(10, entries[0][0]);
        assertEquals(3, entries[0][1]);
        assertEquals(6, entries[0][2]);
        assertEquals(10, entries[1][0]);
        assertEquals(1, entries[1][1]);
        assertEquals(2, entries[1][2]);
    }

    // findTlv: nested tag lookup used for PDOL/AFL/CDOL capture.
    @Test
    public void findTlv_nestedLookup() {
        byte[] fci = hex("6F2C8407A0000000031010A521"
                + "5004564953419F38189F66049F02069F03069F1A0295055F2A029A039C019F3704");
        assertArrayEquals(hex("9F66049F02069F03069F1A0295055F2A029A039C019F3704"),
                EmvCardEmulatorCore.findTlv(fci, 0x9F38));
        assertEquals(null, EmvCardEmulatorCore.findTlv(fci, 0x94));
        byte[] gpo = hex("770E820200009404500306009F360203AA");
        assertArrayEquals(hex("50030600"), EmvCardEmulatorCore.findTlv(gpo, 0x94));
    }

    // Session reset clears PDOL/AFL/CDOL/AC-count alongside ATC/UN/chaining.
    @Test
    public void sessionReset_clearsPdolAflCdolAcCount() {
        EmvCardEmulatorCore.SessionState state = new EmvCardEmulatorCore.SessionState(0x0001);
        state.activePdol = hex("9F3704");
        state.activeAfl = hex("50030600");
        state.activeCdol1 = hex("9F0206");
        state.activeCdol2 = hex("9F02069F3704");
        state.generateAcCount = 2;
        state.reset(0x0001);
        assertEquals(null, state.activePdol);
        assertEquals(null, state.activeAfl);
        assertEquals(null, state.activeCdol1);
        assertEquals(null, state.activeCdol2);
        assertEquals(0, state.generateAcCount);
        assertEquals(0x0001, state.atc);
    }

    // Strict AFL gate: isAflListed decides 6A83 vs serve (service layer uses this).
    @Test
    public void aflListed_gateDecision() {
        byte[] afl = hex("5003060050010200");
        assertTrue(EmvCardEmulatorCore.isAflListed(afl, 10, 3));
        assertTrue(EmvCardEmulatorCore.isAflListed(afl, 10, 6));
        assertTrue(EmvCardEmulatorCore.isAflListed(afl, 10, 1));
        assertFalse(EmvCardEmulatorCore.isAflListed(afl, 10, 7));
        assertFalse(EmvCardEmulatorCore.isAflListed(afl, 8, 1));
        assertFalse(EmvCardEmulatorCore.isAflListed(null, 10, 3));
    }
}

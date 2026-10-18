package de.androidcrypto.android_hce_emulate_a_creditcard;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Local unit tests for the JSON card-profile model ({@link EmvCardProfile}).
 */
public class EmvCardProfileTest {

    private static final String JSON = "{"
            + "\"label\":\"Test Visa\","
            + "\"aid\":\"A0000000031010\","
            + "\"entries\":["
            + "{\"command\":\"00a404000e32504159\",\"response\":\"6f2b84\"},"
            + "{\"command\":\"80a8\",\"response\":\"7781c69f360203a4\",\"prefixMatch\":true}"
            + "]}";

    @Test
    public void parse_roundTrip() {
        EmvCardProfile p = EmvCardProfile.fromJson(JSON);
        assertEquals("Test Visa", p.getLabel());
        assertEquals("a0000000031010", p.getAid());
        assertEquals(2, p.getEntries().size());
        EmvCardProfile back = EmvCardProfile.fromJson(p.toJson());
        assertEquals(2, back.getEntries().size());
    }

    @Test
    public void findResponse_exactMatch() {
        EmvCardProfile p = EmvCardProfile.fromJson(JSON);
        assertEquals("6f2b84", p.findResponse("00a404000e32504159"));
    }

    @Test
    public void findResponse_prefixMatch_gpo() {
        EmvCardProfile p = EmvCardProfile.fromJson(JSON);
        // GPO carries per-transaction PDOL data, only the 80a8 prefix is stable
        assertEquals("7781c69f360203a4",
                p.findResponse("80a80000238321270000000000000010000000000000000978"));
    }

    @Test
    public void findResponse_exactBeatsPrefix() {
        EmvCardProfile.ApduEntry exact =
                new EmvCardProfile.ApduEntry("80a800", "exact", false);
        EmvCardProfile.ApduEntry prefix =
                new EmvCardProfile.ApduEntry("80a8", "prefix", true);
        EmvCardProfile p = new EmvCardProfile("t", "aid", Arrays.asList(exact, prefix));
        assertEquals("exact", p.findResponse("80a800"));
        assertEquals("prefix", p.findResponse("80a81122"));
    }

    @Test
    public void findResponse_unknown_returnsNull() {
        EmvCardProfile p = EmvCardProfile.fromJson(JSON);
        assertNull(p.findResponse("00b2031400"));
        assertNull(p.findResponse(null));
    }

    @Test
    public void validateEntry_acceptsSwLessPairs() {
        assertNull(EmvCardProfile.validateEntry(
                "00a404000e325041592e5359532e444446303100",
                "6f2b840e325041592e5359532e4444463031"));
        // short GPO prefix command + SW-less response is fine (prefix match)
        assertNull(EmvCardProfile.validateEntry("80a8", "7781c69f360203a4"));
    }

    @Test
    public void validateEntry_rejectsBadHex() {
        assertNotNull(EmvCardProfile.validateEntry("00a4040", "6f2b")); // odd length
        assertNotNull(EmvCardProfile.validateEntry("00zz", "6f2b")); // not hex
        assertNotNull(EmvCardProfile.validateEntry("00a4", "6f2b84")); // short cmd
        assertNotNull(EmvCardProfile.validateEntry("", "6f2b"));
        assertNotNull(EmvCardProfile.validateEntry("00a40400", ""));
        assertNotNull(EmvCardProfile.validateEntry(null, "6f2b"));
    }

    @Test
    public void validateEntry_rejectsTrailingSw() {
        // Imported service appends 9000 at tap time; storing it would double-append
        assertNotNull(EmvCardProfile.validateEntry("00b2031400", "7081fb9000"));
    }

    @Test
    public void validateAid_bounds() {
        assertNull(EmvCardProfile.validateAid("a0000000031010"));
        assertNull(EmvCardProfile.validateAid("A000000025"));
        assertNull(EmvCardProfile.validateAid("a000000003")); // 5 bytes, minimum
        assertNotNull(EmvCardProfile.validateAid("a000")); // 2 bytes, too short
        assertNotNull(EmvCardProfile.validateAid("a000000003101001020304050607080900")); // 17B, too long
        assertNotNull(EmvCardProfile.validateAid("zzzz"));
        assertNotNull(EmvCardProfile.validateAid(""));
        assertNotNull(EmvCardProfile.validateAid(null));
    }

    @Test
    public void setters_roundTripThroughJson() {
        EmvCardProfile p = EmvCardProfile.fromJson(JSON);
        p.setLabel("Edited");
        p.setAid("a0000000041010");
        EmvCardProfile.ApduEntry e = p.getEntries().get(0);
        e.setCommand("00b2011400");
        e.setResponse("7081aa");
        e.setPrefixMatch(true);
        EmvCardProfile back = EmvCardProfile.fromJson(p.toJson());
        assertEquals("Edited", back.getLabel());
        assertEquals("a0000000041010", back.getAid());
        assertEquals("00b2011400", back.getEntries().get(0).normalizedCommand());
        assertEquals("7081aa", back.getEntries().get(0).getResponse());
        assertTrue(back.getEntries().get(0).isPrefixMatch());
    }
}

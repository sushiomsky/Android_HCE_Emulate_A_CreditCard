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
}

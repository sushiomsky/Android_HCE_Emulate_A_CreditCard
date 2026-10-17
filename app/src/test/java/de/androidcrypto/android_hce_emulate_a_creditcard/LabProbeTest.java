package de.androidcrypto.android_hce_emulate_a_creditcard;

import org.junit.Test;

import java.util.HashSet;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Local unit tests for {@link LabProbe} (malformed-response cases).
 */
public class LabProbeTest {

    @Test
    public void cases_haveUniqueNamesAndBodies() {
        List<LabProbe.Case> cases = LabProbe.cases();
        assertTrue(cases.size() >= 6);
        HashSet<String> names = new HashSet<>();
        for (LabProbe.Case c : cases) {
            assertTrue("duplicate: " + c.name, names.add(c.name));
            assertTrue(c.body.length > 0);
            assertEquals(c.body.length, c.actual);
        }
    }

    @Test
    public void overstateCase_liesAboutLength() {
        LabProbe.Case c = LabProbe.cases().get(1);
        assertEquals(0x82, c.body[1] & 0xFF);
        assertEquals(0xFFFF, c.declared);
        assertTrue(c.actual < c.declared);
    }

    @Test
    public void boundaryCases_matchPaperThreshold() {
        boolean has138 = false, has139 = false;
        for (LabProbe.Case c : LabProbe.cases()) {
            if (c.declared == 0x138) has138 = true;
            if (c.declared == 0x139) has139 = true;
        }
        assertTrue(has138 && has139);
    }

    @Test
    public void nestedCase_innerLengthExceedsAvailable() {
        for (LabProbe.Case c : LabProbe.cases()) {
            if (c.name.equals("nested-inner-overflow")) {
                assertTrue(c.declared > c.actual);
                return;
            }
        }
        fail("nested-inner-overflow missing");
    }
}

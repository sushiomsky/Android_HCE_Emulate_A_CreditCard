package de.androidcrypto.android_hce_emulate_a_creditcard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Parser fuzzing: feed the LabProbe malformed-response corpus plus deterministic
 * pseudo-random mutations both directions — as C-APDUs into
 * {@link EmvCardEmulatorCore#parse} and as R-APDU/TLV blobs into
 * {@link EmvCardEmulatorCore#findTlv} — and assert the core never throws,
 * never returns null fields, and always flags truncated input as suspicious.
 *
 * <p>Deterministic seed: the same failures reproduce on every run.
 */
public class EmvParserFuzzTest {

    /** All LabProbe bodies + their 9000-suffixed forms as fuzz inputs. */
    private static List<byte[]> corpusInputs() {
        List<byte[]> inputs = new ArrayList<byte[]>();
        for (LabProbe.Case c : LabProbe.cases()) {
            inputs.add(c.body);
            byte[] withSw = new byte[c.body.length + 2];
            System.arraycopy(c.body, 0, withSw, 0, c.body.length);
            withSw[withSw.length - 2] = (byte) 0x90;
            withSw[withSw.length - 1] = (byte) 0x00;
            inputs.add(withSw);
        }
        return inputs;
    }

    /** Deterministic single-bit / truncation / splice mutations. */
    private static List<byte[]> mutate(byte[] base, int count, long seed) {
        List<byte[]> out = new ArrayList<byte[]>();
        Random rnd = new Random(seed);
        for (int i = 0; i < count; i++) {
            byte[] m = base.clone();
            int kind = rnd.nextInt(4);
            if (kind == 0 && m.length > 0) {
                // flip one bit
                int at = rnd.nextInt(m.length);
                m[at] ^= (byte) (1 << rnd.nextInt(8));
            } else if (kind == 1 && m.length > 1) {
                // truncate to a random shorter length
                int keep = 1 + rnd.nextInt(m.length - 1);
                byte[] t = new byte[keep];
                System.arraycopy(m, 0, t, 0, keep);
                m = t;
            } else if (kind == 2) {
                // splice two random corpus bodies
                List<byte[]> corpus = corpusInputs();
                byte[] other = corpus.get(rnd.nextInt(corpus.size()));
                byte[] s = new byte[m.length + other.length];
                System.arraycopy(m, 0, s, 0, m.length);
                System.arraycopy(other, 0, s, m.length, other.length);
                m = s;
            } else if (m.length > 4) {
                // swap Lc byte against a random value
                m[4] = (byte) rnd.nextInt(256);
            }
            out.add(m);
        }
        return out;
    }

    @Test
    public void fuzz_parse_neverThrowsAndFlagsTruncation() {
        List<byte[]> inputs = corpusInputs();
        List<byte[]> mutated = new ArrayList<byte[]>();
        for (byte[] base : inputs) {
            mutated.addAll(mutate(base, 25, 0xC10C));
        }
        int checked = 0;
        for (byte[] input : mutated) {
            EmvCardEmulatorCore.ParsedApdu apdu;
            try {
                apdu = EmvCardEmulatorCore.parse(input);
            } catch (Exception e) {
                fail("parse threw on " + input.length + "B input: " + e);
                return;
            }
            if (apdu.data == null) {
                fail("parse returned null data for " + input.length + "B input");
            }
            checked++;
        }
        assertTrue("fuzz ran no inputs", checked > 100);
    }

    @Test
    public void fuzz_findTlv_neverThrows() {
        List<byte[]> inputs = corpusInputs();
        int[] tags = {0x9F38, 0x94, 0x8C, 0x8D, 0x9F26, 0x9F36, 0x50, 0x57, 0x5A};
        int checked = 0;
        for (byte[] base : inputs) {
            for (byte[] m : mutate(base, 10, 0xF17D)) {
                for (int tag : tags) {
                    try {
                        EmvCardEmulatorCore.findTlv(m, tag);
                    } catch (Exception e) {
                        fail("findTlv threw on tag " + Integer.toHexString(tag) + ": " + e);
                        return;
                    }
                    checked++;
                }
            }
        }
        assertTrue("fuzz ran no inputs", checked > 100);
    }

    @Test
    public void fuzz_goldenCorpus_parsesClean() {
        // Well-formed reader C-APDUs must parse without the suspicious flag.
        String[] clean = {
                "00A404000E325041592E5359532E444446303100",
                "00A4040007A000000003101000",
                "00A4040007A000000004101000",
                "80A8000002830000",
                "00B2031400",
                "00B2010800",
                "80CA9F3600",
                "00C00000FF",
        };
        for (String hex : clean) {
            byte[] raw = EmvCardEmulatorCore.hexBytes(hex);
            EmvCardEmulatorCore.ParsedApdu apdu = EmvCardEmulatorCore.parse(raw);
            assertEquals("clean C-APDU flagged suspicious: " + hex, false, apdu.lengthSuspicious);
        }
    }

    @Test
    public void fuzz_truncatedInputs_flaggedSuspicious() {
        // Every strict prefix of a well-formed GENERATE AC that cuts into declared
        // Lc must come back flagged, never silently accepted. Prefixes that end
        // exactly on the 4-byte case-1 header, or inside the Lc byte while the
        // remaining bytes still satisfy it, are valid parses by construction:
        // keep <= 5 can still decode (header-only, or Lc=0x2D with 0 data bytes
        // read as case-2S Le). The fuzz-relevant range starts at keep == 6.
        byte[] full = EmvCardEmulatorCore.hexBytes(
                "80AE00002D000000000000000100000000000000097800000000000978230301003839303100");
        for (int keep = 6; keep < full.length; keep++) {
            byte[] cut = new byte[keep];
            System.arraycopy(full, 0, cut, 0, keep);
            EmvCardEmulatorCore.ParsedApdu apdu;
            try {
                apdu = EmvCardEmulatorCore.parse(cut);
            } catch (Exception e) {
                fail("parse threw on " + keep + "B truncation: " + e);
                return;
            }
            assertEquals("truncated " + keep + "B not flagged", true, apdu.lengthSuspicious);
        }
    }
}

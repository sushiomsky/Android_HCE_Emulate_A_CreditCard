package de.androidcrypto.android_hce_emulate_a_creditcard;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

/**
 * Local unit tests for {@link TlvUtils} (BER-TLV parsing).
 */
public class TlvUtilsTest {

    @Test
    public void parse_singleByteTag() {
        // TLV example from Crash & Pay, Appendix B: tag 8F, len 1, value 08
        List<TlvUtils.Tlv> tlvs = TlvUtils.parse("8F0108");
        assertEquals(1, tlvs.size());
        assertEquals("8f", tlvs.get(0).tag);
        assertArrayEquals(new byte[]{0x08}, tlvs.get(0).value);
    }

    @Test
    public void parse_twoByteTag() {
        // "9F320103": tag 9F32, len 1, value 03
        List<TlvUtils.Tlv> tlvs = TlvUtils.parse("9F320103");
        assertEquals(1, tlvs.size());
        assertEquals("9f32", tlvs.get(0).tag);
    }

    @Test
    public void parse_longFormLength() {
        // tag 70, long-form length 0x81 0xC9 = 201
        byte[] value = new byte[201];
        String hex = "7081C9" + Utils.bytesToHexNpe(value);
        List<TlvUtils.Tlv> tlvs = TlvUtils.parse(hex);
        assertEquals(1, tlvs.size());
        assertEquals("70", tlvs.get(0).tag);
        assertEquals(201, tlvs.get(0).value.length);
    }

    @Test
    public void summarize_nested() {
        // 77{82[2] 9F36[2]} — response template with AFL + ATC
        String s = TlvUtils.summarize("7709820203009F360203A4");
        assertEquals("77[9]{82[2] 9f36[2]}", s);
    }

    @Test
    public void parse_malformed_returnsPartial() {
        // truncated value: parser stops, keeps nothing half-read
        assertTrue(TlvUtils.parse("70038202").isEmpty());
        assertEquals("not TLV", TlvUtils.summarize("ZZZ"));
        assertEquals("not TLV", TlvUtils.summarize(null));
    }
}

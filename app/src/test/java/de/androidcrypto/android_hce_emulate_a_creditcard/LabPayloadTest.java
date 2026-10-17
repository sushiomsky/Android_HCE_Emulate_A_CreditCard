package de.androidcrypto.android_hce_emulate_a_creditcard;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Local unit tests for {@link LabPayload} (oversized response builder).
 */
public class LabPayloadTest {

    @Test
    public void buildResponse_exactLengthAndPattern() {
        byte[] out = LabPayload.buildResponse(8, new byte[]{0x41});
        assertEquals(8, out.length);
        for (byte b : out) assertEquals(0x41, b);
    }

    @Test
    public void buildResponse_cyclesPattern() {
        byte[] out = LabPayload.buildResponse(5, new byte[]{0x01, 0x02, 0x03});
        assertArrayEquals(new byte[]{0x01, 0x02, 0x03, 0x01, 0x02}, out);
    }

    @Test
    public void buildResponse_zeroLength() {
        assertEquals(0, LabPayload.buildResponse(0, new byte[]{0x41}).length);
    }

    @Test(expected = IllegalArgumentException.class)
    public void buildResponse_rejectsOversize() {
        LabPayload.buildResponse(LabPayload.MAX_LEN + 1, new byte[]{0x41});
    }

    @Test(expected = IllegalArgumentException.class)
    public void buildResponse_rejectsEmptyPattern() {
        LabPayload.buildResponse(16, new byte[0]);
    }
}

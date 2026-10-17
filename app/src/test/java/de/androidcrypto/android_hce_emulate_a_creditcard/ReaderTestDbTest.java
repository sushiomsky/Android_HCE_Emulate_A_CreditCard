package de.androidcrypto.android_hce_emulate_a_creditcard;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Local unit tests for the reader-database record format (pure JSON
 * round-trip; file I/O in {@link ReaderTestDb} needs a device).
 */
public class ReaderTestDbTest {

    @Test
    public void record_jsonRoundTrip() {
        ReaderTestDb.Reader r = new ReaderTestDb.Reader();
        r.fp = "A1B2C3D4";
        r.detail = "[A1B2C3D4] 9F1E=0011223344556677";
        r.model = "VP8300";
        r.fw = "1.2.3";
        ReaderTestDb.Step s = new ReaderTestDb.Step();
        s.time = "12:00:00.000";
        s.step = "probe 2/8 declare-64k";
        s.dwellMs = 42;
        s.verdict = "ANOMALY fast-drop (heuristic)";
        r.steps.add(s);

        Gson gson = new GsonBuilder().create();
        List<ReaderTestDb.Reader> all = new ArrayList<>();
        all.add(r);
        String json = gson.toJson(all);
        List<ReaderTestDb.Reader> back = gson.fromJson(json,
                new TypeToken<List<ReaderTestDb.Reader>>() {
                }.getType());
        assertEquals(1, back.size());
        assertEquals("VP8300", back.get(0).model);
        assertEquals("1.2.3", back.get(0).fw);
        assertEquals(1, back.get(0).steps.size());
        assertEquals(42, back.get(0).steps.get(0).dwellMs);
        assertTrue(back.get(0).steps.get(0).verdict.startsWith("ANOMALY"));
    }
}

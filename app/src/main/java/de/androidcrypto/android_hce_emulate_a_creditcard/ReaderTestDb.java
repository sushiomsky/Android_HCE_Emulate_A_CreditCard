package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.content.SharedPreferences;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Local database of tested readers: terminal fingerprint (captured
 * automatically from GPO PDOL data) plus manually entered model/firmware,
 * with per-step lab outcomes appended automatically during sweep/probe taps.
 * Stored as JSON in internal storage; share it via the session log share.
 */
public final class ReaderTestDb {

    private static final String PREFS = "hce_cc_prefs";
    private static final String KEY_LAST_FP = "last_terminal_fp";
    private static final String FILE = "reader_db.json";

    private ReaderTestDb() {
    }

    public static class Step {
        @SerializedName("t")
        public String time = "";
        @SerializedName("step")
        public String step = "";
        @SerializedName("dwellMs")
        public long dwellMs = -1;
        @SerializedName("verdict")
        public String verdict = "";
    }

    public static class Reader {
        @SerializedName("fp")
        public String fp = "";
        @SerializedName("detail")
        public String detail = "";
        @SerializedName("model")
        public String model = "";
        @SerializedName("fw")
        public String fw = "";
        @SerializedName("steps")
        public List<Step> steps = new ArrayList<>();
    }

    public static void setLastFingerprint(Context context, String fp, String detail) {
        prefs(context).edit().putString(KEY_LAST_FP, fp + "\n" + detail).apply();
    }

    public static String getLastFingerprint(Context context) {
        return prefs(context).getString(KEY_LAST_FP, null);
    }

    public static synchronized void identify(Context context, String fpId, String detail,
                                             String model, String fw) {
        List<Reader> all = loadAll(context);
        Reader r = find(all, fpId);
        if (r == null) {
            r = new Reader();
            r.fp = fpId;
            all.add(r);
        }
        r.detail = detail;
        r.model = model != null ? model : "";
        r.fw = fw != null ? fw : "";
        saveAll(context, all);
    }

    public static synchronized void appendStep(Context context, String fpId,
                                              String step, long dwellMs, String verdict) {
        List<Reader> all = loadAll(context);
        Reader r = find(all, fpId);
        if (r == null) {
            r = new Reader();
            r.fp = fpId;
            all.add(r);
        }
        Step s = new Step();
        s.time = Utils.getTimestampShort();
        s.step = step;
        s.dwellMs = dwellMs;
        s.verdict = verdict;
        r.steps.add(s);
        saveAll(context, all);
    }

    public static synchronized List<Reader> list(Context context) {
        return loadAll(context);
    }

    private static Reader find(List<Reader> all, String fpId) {
        for (Reader r : all) {
            if (r.fp.equals(fpId)) return r;
        }
        return null;
    }

    private static List<Reader> loadAll(Context context) {
        File f = new File(context.getFilesDir(), FILE);
        if (!f.exists()) return new ArrayList<>();
        try {
            byte[] buf = new byte[(int) Math.min(f.length(), 1024 * 1024)];
            try (FileInputStream fis = new FileInputStream(f)) {
                int read = 0;
                while (read < buf.length) {
                    int n = fis.read(buf, read, buf.length - read);
                    if (n < 0) break;
                    read += n;
                }
                List<Reader> parsed = gson().fromJson(
                        new String(buf, 0, read, StandardCharsets.UTF_8),
                        new TypeToken<List<Reader>>() {
                        }.getType());
                return parsed != null ? parsed : new ArrayList<Reader>();
            }
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    private static void saveAll(Context context, List<Reader> all) {
        try {
            byte[] data = gson().toJson(all).getBytes(StandardCharsets.UTF_8);
            try (FileOutputStream fos = new FileOutputStream(new File(context.getFilesDir(), FILE))) {
                fos.write(data);
            }
        } catch (IOException ignored) {
        }
    }

    private static Gson gson() {
        return new GsonBuilder().setPrettyPrinting().create();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}

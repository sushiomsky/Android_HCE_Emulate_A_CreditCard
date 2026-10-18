package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Persists imported {@link EmvCardProfile}s as JSON files in internal storage
 * (no permissions needed) and remembers the active one.
 */
public class CardProfileStore {

    private static final String PREFS = "hce_cc_prefs";
    private static final String KEY_IMPORTED_PROFILE = "imported_profile_file";
    private static final String DIR = "card_profiles";

    private CardProfileStore() {
    }

    public static List<String> list(Context context) {
        List<String> names = new ArrayList<>();
        File dir = dir(context);
        File[] files = dir.listFiles((d, name) -> name.endsWith(".json"));
        if (files != null) {
            for (File f : files) names.add(f.getName());
        }
        return names;
    }

    public static String save(Context context, String fileName, String json) throws IOException {
        String safe = fileName.replaceAll("[^a-zA-Z0-9._-]", "_");
        if (!safe.endsWith(".json")) safe += ".json";
        File dir = dir(context);
        if (!dir.exists() && !dir.mkdirs()) throw new IOException("cannot create profile dir");
        // validate before storing
        EmvCardProfile profile = EmvCardProfile.fromJson(json);
        if (profile == null || profile.getEntries().isEmpty()) {
            throw new IOException("not a valid card profile (no entries)");
        }
        File out = new File(dir, safe);
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(json.getBytes(StandardCharsets.UTF_8));
        }
        return safe;
    }

    public static EmvCardProfile load(Context context, String fileName) throws IOException {
        File in = new File(dir(context), fileName);
        byte[] data = new byte[(int) in.length()];
        try (FileInputStream fis = new FileInputStream(in)) {
            int read = 0;
            while (read < data.length) {
                int n = fis.read(data, read, data.length - read);
                if (n < 0) break;
                read += n;
            }
        }
        return EmvCardProfile.fromJson(new String(data, StandardCharsets.UTF_8));
    }

    public static boolean delete(Context context, String fileName) {
        boolean ok = new File(dir(context), fileName).delete();
        if (fileName.equals(getActiveFileName(context))) {
            setActiveFileName(context, null);
        }
        return ok;
    }

    public static void ensureSampleAsset(Context context, String assetName) {
        if (!list(context).isEmpty()) return;
        try (java.io.InputStream is = context.getAssets().open(assetName)) {
            byte[] buf = new byte[is.available()];
            int read = 0;
            while (read < buf.length) {
                int n = is.read(buf, read, buf.length - read);
                if (n < 0) break;
                read += n;
            }
            save(context, assetName, new String(buf, StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // sample is a convenience, not a requirement
        }
    }

    public static String getActiveFileName(Context context) {
        return prefs(context).getString(KEY_IMPORTED_PROFILE, null);
    }

    public static void setActiveFileName(Context context, String fileName) {
        prefs(context).edit().putString(KEY_IMPORTED_PROFILE, fileName).apply();
    }

    private static File dir(Context context) {
        return new File(context.getFilesDir(), DIR);
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}

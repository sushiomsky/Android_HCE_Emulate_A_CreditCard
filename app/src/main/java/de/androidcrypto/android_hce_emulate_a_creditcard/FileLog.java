package de.androidcrypto.android_hce_emulate_a_creditcard;

import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.getTimestampShort;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Automatic session file logging: every HCE log line is appended to a session
 * file in internal storage (no permissions needed), so a full tap session
 * survives app restarts and can be shared as one file.
 */
public final class FileLog {

    private static final String PREFS = "hce_cc_prefs";
    private static final String KEY_SESSION_FILE = "session_log_file";

    private FileLog() {
    }

    public static synchronized void append(Context context, String message, String data) {
        String line = getTimestampShort() + " | " + message + " | " + data + "\n";
        try {
            File f = currentFile(context);
            try (FileOutputStream fos = new FileOutputStream(f, true)) {
                fos.write(line.getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException ignored) {
        }
    }

    public static synchronized String readAll(Context context) {
        try {
            File f = currentFile(context);
            byte[] buf = new byte[(int) Math.min(f.length(), 2 * 1024 * 1024)];
            try (FileInputStream fis = new FileInputStream(f)) {
                int read = 0;
                while (read < buf.length) {
                    int n = fis.read(buf, read, buf.length - read);
                    if (n < 0) break;
                    read += n;
                }
                return new String(buf, 0, read, StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            return "";
        }
    }

    public static synchronized String currentName(Context context) {
        return currentFile(context).getName();
    }

    /** Starts a fresh session file (call on app start). Returns its name. */
    public static synchronized String newSession(Context context) {
        String name = "session_" + Utils.getTimestampMillisFile() + ".log";
        prefs(context).edit().putString(KEY_SESSION_FILE, name).apply();
        return name;
    }

    private static File currentFile(Context context) {
        SharedPreferences prefs = prefs(context);
        String name = prefs.getString(KEY_SESSION_FILE, null);
        if (name == null) {
            name = newSession(context);
        }
        return new File(context.getFilesDir(), name);
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}

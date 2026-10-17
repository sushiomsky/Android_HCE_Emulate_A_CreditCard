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
 * Pcap-style tap export: raw C-APDU/R-APDU pairs recorded per tap, exported as
 * a human- and machine-readable conversation file (no NFC sniffer needed).
 *
 * <p>Each exchange is one line: {@code C:<hex> R:<hex>} (R includes SW). Lines
 * starting with {@code #} are comments (scheme, tap start/end markers). The
 * file parses with a one-liner: skip {@code #} lines, split on the space, strip
 * the {@code C:} / {@code R:} prefixes.
 *
 * <p>Storage: app-internal files dir, same store key pattern as {@link FileLog}.
 */
public final class TapExport {

    private static final String PREFS = "hce_cc_prefs";
    private static final String KEY_TAP_FILE = "tap_export_file";

    /** Cap so a hostile reader cannot grow storage without bound (~200KB). */
    private static final int MAX_PAIRS_PER_TAP = 500;

    private TapExport() {
    }

    /** One raw command/response exchange. */
    public static final class Exchange {
        public final byte[] command;
        public final byte[] response;

        Exchange(byte[] command, byte[] response) {
            this.command = command;
            this.response = response;
        }
    }

    private static final List<Exchange> pending = new ArrayList<Exchange>();
    private static String pendingScheme = "";

    /** Starts a new tap: drops any unexported exchanges, records the scheme. */
    public static synchronized void beginTap(String scheme) {
        pending.clear();
        pendingScheme = scheme == null ? "" : scheme;
    }

    /** Records one C-APDU/R-APDU pair (copies defensively, caps count). */
    public static synchronized void record(byte[] commandApdu, byte[] responseApdu) {
        if (pending.size() >= MAX_PAIRS_PER_TAP) {
            return;
        }
        pending.add(new Exchange(
                commandApdu == null ? new byte[0] : commandApdu.clone(),
                responseApdu == null ? new byte[0] : responseApdu.clone()));
    }

    /** Number of exchanges recorded since {@link #beginTap}. */
    public static synchronized int pendingCount() {
        return pending.size();
    }

    /**
     * Writes the pending exchanges to a new tap file and clears the buffer.
     * Returns the file name, or null when nothing was recorded.
     */
    public static synchronized String exportTap(Context context) {
        if (pending.isEmpty()) {
            return null;
        }
        String name = "tap_" + Utils.getTimestampMillisFile() + ".apdu";
        File f = new File(context.getFilesDir(), name);
        StringBuilder sb = new StringBuilder();
        sb.append("# HCE tap export scheme=").append(pendingScheme)
                .append(" pairs=").append(pending.size()).append('\n');
        for (Exchange e : pending) {
            sb.append("C:").append(Utils.bytesToHexNpe(e.command))
                    .append(" R:").append(Utils.bytesToHexNpe(e.response)).append('\n');
        }
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            return null;
        }
        pending.clear();
        prefs(context).edit().putString(KEY_TAP_FILE, name).apply();
        return name;
    }

    /** Reads a previously exported tap file back (for share / verification). */
    public static synchronized String readTap(Context context, String name) {
        File f = new File(context.getFilesDir(), name);
        if (!f.exists() || f.length() > 2 * 1024 * 1024) {
            return "";
        }
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] buf = new byte[(int) f.length()];
            int read = 0;
            while (read < buf.length) {
                int n = fis.read(buf, read, buf.length - read);
                if (n < 0) {
                    break;
                }
                read += n;
            }
            return new String(buf, 0, read, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    /** Name of the most recently exported tap, or null. */
    public static synchronized String lastExportName(Context context) {
        return prefs(context).getString(KEY_TAP_FILE, null);
    }

    /**
     * Parses tap-export text back into exchanges (skips {@code #} comments).
     * Pure-Java so unit tests can round-trip without Android.
     */
    public static List<Exchange> parse(String text) {
        List<Exchange> out = new ArrayList<Exchange>();
        if (text == null) {
            return out;
        }
        for (String line : text.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int sep = line.indexOf(" R:");
            if (!line.startsWith("C:") || sep < 0) {
                continue;
            }
            String cHex = line.substring(2, sep);
            String rHex = line.substring(sep + 3).trim();
            try {
                if (cHex.isEmpty() || rHex.isEmpty()) {
                    continue;
                }
                byte[] c = Utils.hexStringToByteArray(cHex);
                byte[] r = Utils.hexStringToByteArray(rHex);
                out.add(new Exchange(c, r));
            } catch (Exception ignored) {
                // skip malformed lines; the file stays parseable
            }
        }
        return out;
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}

package de.androidcrypto.android_hce_emulate_a_creditcard;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A data-driven EMV card profile: an ordered list of command -&gt; response APDU pairs
 * (hex strings) that an HCE service replays, instead of hardcoded static byte arrays.
 *
 * <p>Profiles are exchanged as JSON (GSON), e.g. exported from an NFC reader session:</p>
 * <pre>
 * {
 *   "label": "Sample Visa",
 *   "aid": "a0000000031010",
 *   "entries": [
 *     {"command": "00a404000e3250...", "response": "6f2b84..."},
 *     {"command": "80a8", "response": "7781c6...", "prefixMatch": true}
 *   ]
 * }
 * </pre>
 * <p>An entry with {@code "prefixMatch": true} answers every command starting with the
 * given bytes - used for Get Processing Options (GPO, {@code 80a8}), whose PDOL data
 * changes with each transaction (amount, date, unpredictable number).</p>
 */
public class EmvCardProfile {

    @SerializedName("label")
    private String label;

    @SerializedName("aid")
    private String aid;

    @SerializedName("entries")
    private List<ApduEntry> entries = new ArrayList<>();

    public EmvCardProfile() {
    }

    public EmvCardProfile(String label, String aid, List<ApduEntry> entries) {
        this.label = label;
        this.aid = aid;
        this.entries = entries != null ? entries : new ArrayList<>();
    }

    public String getLabel() {
        return label != null ? label : "";
    }

    public String getAid() {
        return aid != null ? aid.toLowerCase(Locale.US) : "";
    }

    public List<ApduEntry> getEntries() {
        return entries != null ? entries : new ArrayList<>();
    }

    /** Exact match first, then prefix-match entries (e.g. GPO). Returns null if unknown. */
    public String findResponse(String commandHex) {
        if (commandHex == null || entries == null) return null;
        String cmd = commandHex.toLowerCase(Locale.US);
        for (ApduEntry e : getEntries()) {
            if (!e.isPrefixMatch() && cmd.equals(e.normalizedCommand())) return e.getResponse();
        }
        for (ApduEntry e : getEntries()) {
            if (e.isPrefixMatch() && cmd.startsWith(e.normalizedCommand())) return e.getResponse();
        }
        return null;
    }

    public static EmvCardProfile fromJson(String json) {
        return gson().fromJson(json, EmvCardProfile.class);
    }

    public String toJson() {
        return gson().toJson(this);
    }

    private static Gson gson() {
        return new GsonBuilder().setPrettyPrinting().create();
    }

    /** Single command -&gt; response pair, both as hex strings (without trailing 9000). */
    public static class ApduEntry {
        @SerializedName("command")
        private String command;
        @SerializedName("response")
        private String response;
        @SerializedName("prefixMatch")
        private boolean prefixMatch;

        public ApduEntry() {
        }

        public ApduEntry(String command, String response, boolean prefixMatch) {
            this.command = command;
            this.response = response;
            this.prefixMatch = prefixMatch;
        }

        public String normalizedCommand() {
            return command != null ? command.toLowerCase(Locale.US) : "";
        }

        public String getResponse() {
            return response != null ? response.toLowerCase(Locale.US) : "";
        }

        public boolean isPrefixMatch() {
            return prefixMatch;
        }
    }
}

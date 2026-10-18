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

    public void setLabel(String label) {
        this.label = label;
    }

    public String getAid() {
        return aid != null ? aid.toLowerCase(Locale.US) : "";
    }

    public void setAid(String aid) {
        this.aid = aid;
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

    /**
     * Validates one APDU pair the way the profile editor does (same rules,
     * pure-Java so unit tests can pin them). Returns null when valid, otherwise
     * a short human-readable reason. Responses must be SW-less bodies — the
     * Imported service appends {@code 9000} at tap time, so a trailing SW here
     * would double-append.
     */
    public static String validateEntry(String commandHex, String responseHex) {
        if (commandHex == null || responseHex == null) return "empty command/response";
        String c = commandHex.trim();
        String r = responseHex.trim();
        if (c.isEmpty() || r.isEmpty()) return "empty command/response";
        if (c.length() % 2 != 0) return "command hex must have an even length";
        if (r.length() % 2 != 0) return "response hex must have an even length";
        if (!c.matches("[0-9a-fA-F]+")) return "command is not hex";
        if (!r.matches("[0-9a-fA-F]+")) return "response is not hex";
        // short prefixes are allowed: GPO uses prefix match (PDOL changes each tap)
        boolean isGpoPrefix = c.equalsIgnoreCase("80a8");
        if (c.length() < 8 && !isGpoPrefix) return "command shorter than a 4-byte APDU header";
        if (r.toLowerCase(Locale.US).endsWith("9000")) {
            return "response must not end with 9000 (SW is appended at tap time)";
        }
        return null;
    }

    /**
     * Validates an AID hex string (5-16 bytes per ISO 7816-5). Null when valid,
     * otherwise a short reason.
     */
    public static String validateAid(String aidHex) {
        if (aidHex == null || aidHex.trim().isEmpty()) return "empty AID";
        String a = aidHex.trim();
        if (a.length() % 2 != 0) return "AID hex must have an even length";
        if (!a.matches("[0-9a-fA-F]+")) return "AID is not hex";
        if (a.length() < 10 || a.length() > 32) return "AID must be 5-16 bytes";
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

        public void setCommand(String command) {
            this.command = command;
        }

        public void setResponse(String response) {
            this.response = response;
        }

        public void setPrefixMatch(boolean prefixMatch) {
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

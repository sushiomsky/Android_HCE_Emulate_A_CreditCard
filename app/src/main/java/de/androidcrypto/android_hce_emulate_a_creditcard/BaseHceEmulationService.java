package de.androidcrypto.android_hce_emulate_a_creditcard;

import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.INS_GENERATE_AC;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.INS_GET_DATA;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.INS_GET_RESPONSE;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.INS_GPO;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.INS_READ_RECORD;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.INS_SELECT;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.SW_CONDITIONS_NOT_SATISFIED;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.SW_FILE_NOT_FOUND;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.SW_INS_NOT_SUPPORTED;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.SW_OK;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.SW_WRONG_LENGTH;
import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.concat;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.arrayBeginsWith;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.bytesToHexNpe;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.hexStringToByteArray;

import android.content.Context;
import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.util.HashMap;
import java.util.Map;

/**
 * Shared base class for the HCE credit-card emulation services.
 *
 * <p>Research / interoperability fixture: all PANs are EMVCo 3-D Secure test
 * profiles (Visa 4111...1111, Mastercard 5555...4444, Amex/Discover test ranges).
 * No real cardholder data is present. Replayed cryptograms cannot authorize a
 * transaction; the services exist for reader-compatibility lab testing only.
 *
 * <p>Each tap runs a fresh {@link EmvCardEmulatorCore.SessionState}: ATC starts at
 * the profile default and increments per GPO; UN bytes from the terminal PDOL are
 * echoed into the GPO template; {@code onDeactivated} resets the session so the
 * next tap starts clean.
 */
public abstract class BaseHceEmulationService extends HostApduService {

    /** Optional ATC -&gt; CVC3 dictionary patch applied to tag 9F62 on GPO. Null = disabled. */
    protected Map<Integer, byte[]> cvc3ByAtc;

    /** Upper bound for the first chunk before 61xx chaining kicks in. */
    protected int maxFirstChunk = 255;

    private final EmvCardEmulatorCore.SessionState sessionState =
            new EmvCardEmulatorCore.SessionState(getInitialAtc());

    private byte[] selectPpseResponse;
    private byte[] selectAidResponse;
    private byte[] gpoTemplate;
    private Map<String, byte[]> readRecords;
    private byte[] generateAcTemplate;
    private Map<String, byte[]> getDataObjects;

    protected abstract String getSchemeName();

    protected abstract int getInitialAtc();

    protected abstract void initProfile();

    /**
     * Called once (lazily) to register this scheme's static templates.
     * All PANs below must be EMVCo test profiles, never real card numbers.
     */
    protected final void setProfile(byte[] ppseResponse, byte[] aidResponse, byte[] gpoResponseTemplate,
            Map<String, byte[]> records, byte[] acTemplate, Map<String, byte[]> dataObjects) {
        this.selectPpseResponse = ppseResponse;
        this.selectAidResponse = aidResponse;
        this.gpoTemplate = gpoResponseTemplate;
        this.readRecords = records == null ? new HashMap<String, byte[]>() : records;
        this.generateAcTemplate = acTemplate;
        this.getDataObjects = dataObjects == null ? new HashMap<String, byte[]>() : dataObjects;
    }

    private boolean profileReady;
    private final Object profileLock = new Object();

    private void ensureProfile() {
        if (profileReady) {
            return;
        }
        synchronized (profileLock) {
            if (!profileReady) {
                initProfile();
                profileReady = true;
            }
        }
    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle bundle) {
        ensureProfile();
        EmvCardEmulatorCore.ParsedApdu apdu = EmvCardEmulatorCore.parse(commandApdu);
        log("[" + getSchemeName() + "] C-APDU", bytesToHexNpe(commandApdu)
                + apduLengthNote(apdu));
        if (apdu.lengthSuspicious) {
            log("[" + getSchemeName() + "] length warning", apdu.lengthNote);
        }

        // GET RESPONSE chaining: deliver pending bytes from a previous 61xx.
        if (apdu.ins == INS_GET_RESPONSE) {
            return servePendingChainedBytes();
        }

        // SELECT (P1=04: by DF name / AID). Dispatch on P1/P2 + Lc content, not byte-exact match.
        if (apdu.ins == INS_SELECT && (apdu.p1 == (byte) 0x04) && (apdu.p2 == (byte) 0x00)) {
            return handleSelect(apdu);
        }

        // GET PROCESSING OPTIONS: dynamic UN echo + ATC increment.
        if (apdu.cla == (byte) 0x80 && apdu.ins == INS_GPO) {
            byte[] dynamic = EmvCardEmulatorCore.buildDynamicGpoResponse(
                    gpoTemplate, apdu.data, sessionState, cvc3ByAtc);
            log("[" + getSchemeName() + "] GPO dynamic",
                    "atc=" + String.format("%04X", sessionState.atc)
                            + " un=" + bytesToHexNpe(sessionState.lastUnpredictableNumber));
            return maybeChain(dynamic);
        }

        // READ RECORD: P1 = record number, P2 = (SFI &lt;&lt; 3) | 4.
        if (apdu.ins == INS_READ_RECORD) {
            return handleReadRecord(apdu);
        }

        // GENERATE AC: acknowledge with a static template + SW (lab replay fixture).
        if (apdu.cla == (byte) 0x80 && apdu.ins == INS_GENERATE_AC) {
            log("[" + getSchemeName() + "] GENERATE AC",
                    "p1=" + String.format("%02X", apdu.p1) + " lc=" + apdu.data.length);
            if (generateAcTemplate != null) {
                return maybeChain(generateAcTemplate);
            }
            return concat(new byte[0], SW_CONDITIONS_NOT_SATISFIED);
        }

        // GET DATA: P1P2 = tag (e.g. 9F36 ATC, 9F13, 9F17).
        if (apdu.cla == (byte) 0x80 && apdu.ins == INS_GET_DATA) {
            return handleGetData(apdu);
        }

        log("[" + getSchemeName() + "] unsupported INS",
                String.format("cla=%02X ins=%02X", apdu.cla, apdu.ins));
        return concat(new byte[0], SW_INS_NOT_SUPPORTED);
    }

    private byte[] handleSelect(EmvCardEmulatorCore.ParsedApdu apdu) {
        String route = EmvCardEmulatorCore.routeSelect(apdu.data);
        if ("ppse".equals(route)) {
            log("[" + getSchemeName() + "] SELECT PPSE", bytesToHexNpe(apdu.data));
            return maybeChain(selectPpseResponse);
        }
        if ("unknown".equals(route)) {
            log("[" + getSchemeName() + "] SELECT unknown DF",
                    bytesToHexNpe(apdu.data));
            return concat(new byte[0], SW_FILE_NOT_FOUND);
        }
        log("[" + getSchemeName() + "] SELECT AID (" + route + ")",
                bytesToHexNpe(apdu.data));
        if (!route.equalsIgnoreCase(getSchemeName())
                && !("visa".equals(route) && "visa".equalsIgnoreCase(getSchemeName()))) {
            // Cross-scheme SELECT routed to the wrong service: still answer with our
            // profile so multi-AID readers get a well-formed FCI, and note it in the log.
            log("[" + getSchemeName() + "] cross-scheme SELECT",
                    "requested=" + route + " served=" + getSchemeName());
        }
        return maybeChain(selectAidResponse);
    }

    private byte[] handleReadRecord(EmvCardEmulatorCore.ParsedApdu apdu) {
        int record = apdu.p1 & 0xFF;
        int sfi = (apdu.p2 & 0xFF) >> 3;
        String key = sfi + "/" + record;
        log("[" + getSchemeName() + "] READ RECORD", "sfi=" + sfi + " rec=" + record);
        byte[] record_data = readRecords.get(key);
        if (record_data == null) {
            return concat(new byte[0], SW_FILE_NOT_FOUND);
        }
        return maybeChain(record_data);
    }

    private byte[] handleGetData(EmvCardEmulatorCore.ParsedApdu apdu) {
        String tag = String.format("%02X%02X", apdu.p1, apdu.p2);
        // Dynamic ATC read: always reflect the live session counter.
        if ("9F36".equals(tag)) {
            byte[] atcBytes = new byte[]{
                    (byte) ((sessionState.atc >> 8) & 0xFF),
                    (byte) (sessionState.atc & 0xFF)};
            log("[" + getSchemeName() + "] GET DATA 9F36",
                    "atc=" + String.format("%04X", sessionState.atc));
            return maybeChain(atcBytes);
        }
        byte[] value = getDataObjects.get(tag);
        if (value == null) {
            log("[" + getSchemeName() + "] GET DATA unknown tag", tag);
            return concat(new byte[0], SW_FILE_NOT_FOUND);
        }
        log("[" + getSchemeName() + "] GET DATA", tag);
        return maybeChain(value);
    }

    /**
     * Return the response, using 61xx + GET RESPONSE chaining when it exceeds
     * {@link #maxFirstChunk}. The remainder is held in session state (improvement 5).
     */
    private byte[] maybeChain(byte[] responseWithoutSw) {
        if (responseWithoutSw == null) {
            return concat(new byte[0], SW_WRONG_LENGTH);
        }
        byte[][] chained = EmvCardEmulatorCore.chainResponse(responseWithoutSw, maxFirstChunk);
        if (chained[1] == null) {
            return concat(chained[0], SW_OK);
        }
        sessionState.pendingChainedResponse = chained[1];
        log("[" + getSchemeName() + "] 61xx chaining",
                "first=" + chained[0].length + " pending=" + chained[1].length);
        return concat(chained[0], EmvCardEmulatorCore.statusRemaining(chained[1].length));
    }

    private byte[] servePendingChainedBytes() {
        byte[] pending = sessionState.pendingChainedResponse;
        if (pending == null || pending.length == 0) {
            sessionState.pendingChainedResponse = null;
            return concat(new byte[0], SW_WRONG_LENGTH);
        }
        byte[][] chained = EmvCardEmulatorCore.chainResponse(pending, maxFirstChunk);
        if (chained[1] == null) {
            sessionState.pendingChainedResponse = null;
            return concat(chained[0], SW_OK);
        }
        sessionState.pendingChainedResponse = chained[1];
        return concat(chained[0], EmvCardEmulatorCore.statusRemaining(chained[1].length));
    }

    @Override
    public void onDeactivated(int reason) {
        // Session reset (improvement 3): ATC, last UN and chaining state restart each tap.
        sessionState.reset(getInitialAtc());
        String name = reason == 1 ? "DESELECTED" : reason == 0 ? "LINK_LOSS" : "unknown(" + reason + ")";
        log("onDeactivated",
                "reason=" + name + " session reset, atc="
                        + String.format("%04X", sessionState.atc));
    }

    private String apduLengthNote(EmvCardEmulatorCore.ParsedApdu apdu) {
        StringBuilder note = new StringBuilder();
        note.append(String.format(" cla=%02X ins=%02X p1=%02X p2=%02X lc=%d le=%d%s",
                apdu.cla, apdu.ins, apdu.p1, apdu.p2, apdu.data.length, apdu.le,
                apdu.extendedLength ? " ext" : ""));
        if (apdu.lengthSuspicious) {
            note.append(" SUSPICIOUS: ").append(apdu.lengthNote);
        }
        // arrayBeginsWith is used for the PPSE fast-path hint in logs.
        byte[] ppsePrefix = hexStringToByteArray("00A40400");
        if (arrayBeginsWith(new byte[]{apdu.cla, apdu.ins, apdu.p1, apdu.p2}, ppsePrefix)) {
            note.append(" (select-header)");
        }
        return note.toString();
    }

    private void log(String msg, String data) {
        String prefix = "[" + getSchemeName() + "] ";
        String tlvSummary = "";
        if (msg.endsWith("Response") || msg.contains("GPO dynamic") || msg.contains("GENERATE AC")) {
            try {
                tlvSummary = " | " + TlvUtils.summarize(data);
            } catch (Exception ignored) {
            }
        }
        Intent intent = new Intent("HceCcEmulatorService");
        intent.putExtra("Message", prefix + msg);
        intent.putExtra("Data", data + tlvSummary);
        Context context = this;
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
        FileLog.append(context, prefix + msg, data + tlvSummary);
    }
}

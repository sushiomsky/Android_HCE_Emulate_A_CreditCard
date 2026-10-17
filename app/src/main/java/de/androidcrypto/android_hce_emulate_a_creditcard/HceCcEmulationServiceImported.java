package de.androidcrypto.android_hce_emulate_a_creditcard;

import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.bytesToHexNpe;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.concatenateByteArrays;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.hexStringToByteArray;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.incrementAtc;

import android.content.Context;
import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

/**
 * Data-driven HCE service: answers APDUs from an imported {@link EmvCardProfile}
 * (JSON) instead of hardcoded static byte arrays.
 *
 * <p>The active profile is re-read from internal storage on every tap, so re-importing
 * takes effect without reinstalling the app. GPO answers ({@code 80a8...} prefix match)
 * get a live Application Transaction Counter (ATC) via {@link Utils#incrementAtc}.</p>
 *
 * <p>Unknown commands return {@code 6A82} (file/record not found) rather than a
 * misleading {@code 9000}, so a reader log shows exactly which step is unimplemented.</p>
 */
public class HceCcEmulationServiceImported extends HostApduService {

    private static final byte[] RESPONSE_OK_SW = hexStringToByteArray("9000");
    private static final byte[] RESPONSE_UNKNOWN_SW = hexStringToByteArray("6A82");

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle bundle) {
        sendMessageToActivity("------------------------", "----");
        sendMessageToActivity("# Imported Card #", bytesToHexNpe(commandApdu));

        String active = CardProfileStore.getActiveFileName(this);
        if (active == null) {
            sendMessageToActivity("no imported profile active", "import a card JSON first");
            return RESPONSE_UNKNOWN_SW;
        }
        EmvCardProfile profile;
        try {
            profile = CardProfileStore.load(this, active);
        } catch (Exception e) {
            sendMessageToActivity("cannot load profile", String.valueOf(e.getMessage()));
            return RESPONSE_UNKNOWN_SW;
        }

        String cmdHex = bytesToHexNpe(commandApdu);
        String responseHex = profile.findResponse(cmdHex);
        if (responseHex == null) {
            sendMessageToActivity("unknown command", cmdHex + " -> 6A82");
            return RESPONSE_UNKNOWN_SW;
        }
        boolean isGpo = cmdHex.length() >= 4 && cmdHex.startsWith("80a8");
        if (isGpo) {
            responseHex = incrementAtc(responseHex);
        }
        sendMessageToActivity("profile [" + profile.getLabel() + "] cmd", cmdHex);
        sendMessageToActivity("profile [" + profile.getLabel() + "] resp", responseHex);
        sendMessageToActivity("profile [" + profile.getLabel() + "] TLV", TlvUtils.summarize(responseHex));
        return concatenateByteArrays(hexStringToByteArray(responseHex), RESPONSE_OK_SW);
    }

    @Override
    public void onDeactivated(int reason) {
        sendMessageToActivity("------------------------", "----");
        sendMessageToActivity("onDeactivated with reason", String.valueOf(reason));
    }

    private void sendMessageToActivity(String msg, String data) {
        Intent intent = new Intent("HceCcEmulatorService");
        intent.putExtra("Message", msg);
        intent.putExtra("Data", data);
        Context context = this;
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
        FileLog.append(context, "[imported] " + msg, data);
    }
}

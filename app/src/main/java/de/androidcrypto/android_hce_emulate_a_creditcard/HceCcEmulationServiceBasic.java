package de.androidcrypto.android_hce_emulate_a_creditcard;

import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.bytesToHexNpe;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.concatenateByteArrays;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.hexStringToByteArray;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.nio.charset.StandardCharsets;

public class HceCcEmulationServiceBasic extends HostApduService {

    private static final byte[] RESPONSE_OK_SW = hexStringToByteArray("9000");

    private long lastRespTime = 0;
    private String lastStep = "";

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle bundle) {
        String cmdHex = bytesToHexNpe(commandApdu);
        int cmdLen = commandApdu != null ? commandApdu.length : 0;
        sendMessageToActivity("# processCommandApdu received", cmdLen + "B " + cmdHex);
        //sendUsingStaticallyRegisteredBroadcastReceiver("# processCommandApdu received " + bytesToHexNpe(bytes));
        System.out.println("processCommandApdu: " + cmdHex);
        if (commandApdu != null) {
            System.out.println("processCommandApdu: " + new String(commandApdu, StandardCharsets.UTF_8));
        }

        // Lab mode: answer with an oversized response body to robustness-test your own
        // contactless reader (long/extended APDUs). Off by default.
        SharedPreferences prefs = getSharedPreferences("hce_cc_prefs", Context.MODE_PRIVATE);
        if (prefs.getBoolean("lab_long_response", false)) {
            // Malformed-probe mode: each tap serves the next 0x82-length-confusion
            // case (declared vs. actually sent lengths differ on purpose).
            if (prefs.getBoolean("lab_probe", false)) {
                java.util.List<LabProbe.Case> cases = LabProbe.cases();
                int idx = prefs.getInt("lab_probe_index", 0);
                LabProbe.Case probe = cases.get(idx % cases.size());
                prefs.edit().putInt("lab_probe_index", idx + 1).apply();
                lastStep = "probe " + (idx % cases.size() + 1) + "/" + cases.size()
                        + " " + probe.name;
                sendMessageToActivity("lab probe step", lastStep
                        + " declared " + probe.declared + "B, sent " + probe.actual + "B");
                sendMessageToActivity("lab response", "cmd " + cmdLen + "B -> "
                        + probe.actual + " bytes + 9000");
                lastRespTime = android.os.SystemClock.elapsedRealtime();
                return concatenateByteArrays(probe.body, RESPONSE_OK_SW);
            }
            int len = prefs.getInt("lab_response_len", 512);
            // Auto-sweep: each new tap session (starts with SELECT PPSE) steps to the
            // next length, so one tap series covers 256B..64KB without touching the phone.
            if (prefs.getBoolean("lab_auto_sweep", false) && isSelectPpse(cmdHex)) {
                int idx = prefs.getInt("lab_sweep_index", 0);
                len = LabPayload.SWEEP_LENGTHS[idx % LabPayload.SWEEP_LENGTHS.length];
                prefs.edit().putInt("lab_sweep_index", idx + 1).apply();
                sendMessageToActivity("lab sweep step", (idx % LabPayload.SWEEP_LENGTHS.length + 1)
                        + "/" + LabPayload.SWEEP_LENGTHS.length + " -> " + len + " bytes");
            }
            if (len < 0) len = 0;
            if (len > LabPayload.MAX_LEN) len = LabPayload.MAX_LEN;
            byte[] pattern = hexStringToByteArray(prefs.getString("lab_pattern", "41"));
            if (pattern.length == 0) pattern = hexStringToByteArray("41");
            byte[] body = LabPayload.buildResponse(len, pattern);
            lastStep = len + " bytes";
            sendMessageToActivity("lab response", "cmd " + cmdLen + "B -> " + len + " bytes + 9000");
            lastRespTime = android.os.SystemClock.elapsedRealtime();
            return concatenateByteArrays(body, RESPONSE_OK_SW);
        }

        // in any other case response an 'OK'
        return RESPONSE_OK_SW;
    }

    private static boolean isSelectPpse(String cmdHex) {
        return cmdHex != null && cmdHex.startsWith("00a404000e325041592e5359532e4444463031");
    }

    @Override
    public void onDeactivated(int reason) {
        String name = reason == 1 ? "DESELECTED" : reason == 0 ? "LINK_LOSS" : "unknown(" + reason + ")";
        sendMessageToActivity("onDeactivated with reason", name);
        // reader dwell: how long the reader kept the field up after our last
        // response. An instant drop right after a big/malformed step hints the
        // reader choked instead of processing normally.
        if (lastRespTime > 0) {
            long dwell = android.os.SystemClock.elapsedRealtime() - lastRespTime;
            sendMessageToActivity("reader dwell", dwell + "ms after " + lastStep);
            lastRespTime = 0;
            lastStep = "";
        }
    }

    /**
     * A utility method to send data with an Broadcast Intent from this service to the MainActivity class
     *
     * @param msg
     * @param data
     */
    private void sendMessageToActivity(String msg, String data) {
        Intent intent = new Intent("HceCcEmulatorService");
        // You can also include some extra data.
        intent.putExtra("Message", msg);
        intent.putExtra("Data", data);
        Context context = this;
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
        FileLog.append(context, "[basic] " + msg, data);
    }

}

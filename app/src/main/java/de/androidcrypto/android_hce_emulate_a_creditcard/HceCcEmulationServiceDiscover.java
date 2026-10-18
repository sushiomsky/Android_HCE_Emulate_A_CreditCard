package de.androidcrypto.android_hce_emulate_a_creditcard;

import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.hexBytes;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.hexStringToByteArray;

import java.util.HashMap;
import java.util.Map;

/**
 * Research / interoperability fixture: emulates a Discover card carrying the
 * EMVCo test PAN 6011111111111117 (AID A000000152). Lab testing only; the
 * static cryptogram material cannot authorize a transaction.
 */
public class HceCcEmulationServiceDiscover extends BaseHceEmulationService {

    @Override
    protected String getSchemeName() {
        return "discover";
    }

    @Override
    protected int getInitialAtc() {
        return 0x0001;
    }

    @Override
    protected void initProfile() {
        Map<String, byte[]> records = new HashMap<String, byte[]>();
        records.put("1/1", hexStringToByteArray("70235A0860111111111111175F34010157136011111111111117D230302112794329000000"));
        records.put("1/2", hexStringToByteArray("700E9F6C0200019F6206000000000000"));
        Map<String, byte[]> dataObjects = new HashMap<String, byte[]>();
        dataObjects.put("9F13", hexBytes("00000000000000000000000000000000"));
        dataObjects.put("9F17", hexBytes("00000000"));
        setProfile(
                hexStringToByteArray("6F3B840E325041592E5359532E4444463031A529BF0C2661244F05A0000001525011446973636F7665722054657374436172648701019F0A0400010101"),
                hexStringToByteArray("6F338405A000000152A52A5011446973636F7665722054657374436172648701019F38119F66049F02069F03069F1A0295059F3704"),
                hexStringToByteArray("7712820219809408080101001001010120010200"),
                records,
                hexStringToByteArray("7712820297809408080101001001010120010200"),
                dataObjects);
    }
}

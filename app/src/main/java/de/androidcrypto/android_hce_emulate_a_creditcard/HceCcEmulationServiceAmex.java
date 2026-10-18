package de.androidcrypto.android_hce_emulate_a_creditcard;

import static de.androidcrypto.android_hce_emulate_a_creditcard.EmvCardEmulatorCore.hexBytes;
import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.hexStringToByteArray;

import java.util.HashMap;
import java.util.Map;

/**
 * Research / interoperability fixture: emulates an Amex card carrying the EMVCo
 * test PAN 378282246310005 (AID A000000025). Lab testing only; the static
 * cryptogram material cannot authorize a transaction.
 */
public class HceCcEmulationServiceAmex extends BaseHceEmulationService {

    @Override
    protected String getSchemeName() {
        return "amex";
    }

    @Override
    protected int getInitialAtc() {
        return 0x0001;
    }

    @Override
    protected void initProfile() {
        Map<String, byte[]> records = new HashMap<String, byte[]>();
        // Minimal Amex record set with the test PAN in tag 5A (BCD) and a
        // track-2 equivalent placeholder.
        records.put("1/1", hexStringToByteArray("701B5A08378282246310005F3401019F0702FFC09F0D05B450840000"));
        records.put("1/2", hexStringToByteArray("700E9F6C0200019F6206000000000000"));
        Map<String, byte[]> dataObjects = new HashMap<String, byte[]>();
        dataObjects.put("9F13", hexBytes("00000000000000000000000000000000"));
        dataObjects.put("9F17", hexBytes("00000000"));
        setProfile(
                hexStringToByteArray("6F37840E325041592E5359532E4444463031A525BF0C2261204F05A000000025500D416D65782054657374436172648701019F0A0400010101"),
                hexStringToByteArray("6F2F8405A000000025A526500D416D65782054657374436172648701019F38119F66049F02069F03069F1A0295059F3704"),
                hexStringToByteArray("7712820219809408080101001001010120010200"),
                records,
                hexStringToByteArray("7712820297809408080101001001010120010200"),
                dataObjects);
    }
}

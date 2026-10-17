# Loopback test harness (improvement 7)

The `EmvLoopbackHarnessTest` unit test replays the EMV conversation as a byte
loopback on the JVM - no NFC hardware, no second phone needed.

## What it covers

| # | Improvement | Test |
|---|-------------|------|
| 1 | APDU parser dispatches on CLA/INS/P1/P2/Lc (SELECT A4, GPO A8, READ B2, GENERATE AC AE, GET DATA CA, GET RESPONSE C0) | `parseSelectPpse_fields`, `parseSelectAid_routingPerAid`, `parseGpo_case4ShortLc`, `readerConversation_allInstructionsParse` |
| 2 | Dynamic GPO: terminal UN echoed, ATC incremented per tap, optional CVC3 dictionary | `gpoDynamic_unEchoAndAtcIncrement`, `gpoDynamic_cvc3DictionaryPatch` |
| 4 | Per-AID routing incl. Amex A000000025 + Discover A000000152 | `parseSelectAid_routingPerAid` |
| 5 | Extended-length APDU accept + 61xx/GET RESPONSE chaining + absurd-Lc flagging | `parseExtendedLength_accepts`, `parseAbsurdShortLc_flagged`, `chaining_splitAndStatus` |
| 6 | `arrayBeginsWith` prefix matching | `prefixMatch_gpoHeader` |

## Run it

```bash
export ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk
./gradlew :app:testDebugUnitTest --tests \
  'de.androidcrypto.android_hce_emulate_a_creditcard.EmvLoopbackHarnessTest'
```

Pure-JVM alternative (no Gradle): `EmvCardEmulatorCore` has zero Android
imports, so it compiles standalone:

```bash
javac -d /tmp/emv-core \
  app/src/main/java/de/androidcrypto/android_hce_emulate_a_creditcard/EmvCardEmulatorCore.java
```

## Vs the TalkToYourCreditCard app

[TalkToYourCreditCardG8](https://github.com/AndroidCrypto/TalkToYourCreditCardG8)
is the physical-reader side: it drives a real card over NFC and logs every
C-APDU/R-APDU pair (the `Sample_*_Reader_Logfile.md` traces in this repo came
from it). The loopback harness is the mirror image: it feeds the same C-APDUs
(SELECT PPSE, SELECT AID, GPO, READ RECORD, GENERATE AC, GET DATA, GET RESPONSE)
into the emulator core and asserts the R-APDU shape. Use the reader app for
on-device NFC validation; use the harness for fast regression checks of the
parser, dynamic GPO, and chaining logic.

Suggested on-device flow with the reader app:

1. Install this HCE app on phone A, set it as the default payment app.
2. Run TalkToYourCreditCard on phone B (or a USB NFC reader + its desktop tool).
3. Tap: PPSE select -> AID select -> GPO (check log shows the reader's UN and
   ATC+1) -> READ RECORDs -> GENERATE AC -> GET DATA 9F36 (ATC matches).
4. Deactivate (move phones apart) and tap again: ATC must increment from the
   profile default, proving the session reset.

# Loopback test harness (improvement 7)

The `EmvLoopbackHarnessTest` unit test replays the EMV conversation as a byte
loopback on the JVM - no NFC hardware, no second phone needed.

## What it covers

| # | Improvement | Test |
|---|-------------|------|
| 1 | APDU parser dispatches on CLA/INS/P1/P2/Lc (SELECT A4, GPO A8, READ B2, GENERATE AC AE, GET DATA CA, GET RESPONSE C0) | `parseSelectPpse_fields`, `parseSelectAid_routingPerAid`, `parseGpo_case4ShortLc`, `readerConversation_allInstructionsParse` |
| 2 | Dynamic GPO: terminal UN echoed, ATC incremented per tap, optional CVC3 dictionary | `gpoDynamic_unEchoAndAtcIncrement`, `gpoDynamic_cvc3DictionaryPatch`, `pdolDriven_unLocatedByPdol` |
| 3 | GENERATE AC cryptogram-type decode (ARQC/TC/AAC from P1) | `acType_decodeFromP1` |
| 4 | Per-AID routing incl. Amex A000000025 + Discover A000000152 | `parseSelectAid_routingPerAid` |
| 5 | Extended-length APDU accept + 61xx/GET RESPONSE chaining + absurd-Lc flagging | `parseExtendedLength_accepts`, `parseAbsurdShortLc_flagged`, `chaining_splitAndStatus` |
| 6 | `arrayBeginsWith` prefix matching | `prefixMatch_gpoHeader` |
| 8 | PDOL-driven UN (real 9F38 field walk), AFL ranges, nested TLV lookup, session reset incl. PDOL/AFL/CDOL/AC-count | `pdolDriven_unLocatedByPdol`, `afl_parseRanges`, `findTlv_nestedLookup`, `sessionReset_clearsPdolAflCdolAcCount` |

## Golden-trace tests (`EmvGoldenTraceTest`)
One full tap per scheme through `EmvCardEmulatorCore.simulateTap` — SELECT PPSE,
SELECT AID, GPO (UN echo + ATC + AFL capture), the reader's READ RECORDs
(AFL-listed gate + fixture presence), GENERATE AC template check, live-ATC
GET DATA. C-APDUs come from the repo's sample reader logs:

- `visa_goldenTap`: sample-log PDOL values (33B), reads `00B2031400…00B2061400`
  (wire SFI 2 — AFL byte `0x10`; the log labels it SFI 10, the pre-shift byte).
- `mastercard_goldenTap`: null-PDOL GPO, reads `00B2010800/1000/2000/00B2022000`
  (wire SFI 1/2/4 — the log labels them SFI 8/10/20, the pre-shift P2 bytes).
- `amex_goldenTap` / `discover_goldenTap`: 27B PDOL values, reads SFI 1/2.

## Run it

```bash
export ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk
./gradlew :app:testDebugUnitTest --tests \
  'de.androidcrypto.android_hce_emulate_a_creditcard.EmvLoopbackHarnessTest' \
  --tests 'de.androidcrypto.android_hce_emulate_a_creditcard.EmvGoldenTraceTest' \
  --tests 'de.androidcrypto.android_hce_emulate_a_creditcard.EmvParserFuzzTest'
```

## Parser fuzzing (`EmvParserFuzzTest`)

Deterministic-seed fuzzing (same failures reproduce every run): the LabProbe
malformed-response corpus plus bit-flip / truncation / splice / Lc-swap
mutations go both directions — as C-APDUs into `parse`, as TLV blobs into
`findTlv`. Asserts: never throws, never null fields, well-formed reader
C-APDUs stay unflagged, every truncation into declared Lc is flagged
suspicious.

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

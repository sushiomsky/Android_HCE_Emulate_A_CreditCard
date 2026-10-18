# User Manual — HCE Credit Card Emulator (EMV Lab Fixture)

> **Read this first.** This app replays **EMVCo 3-D Secure test PANs only**
> (Visa `4111111111111111`, Mastercard `5555555555554444`,
> Amex `378282246310005`, Discover `6011111111111117`). It holds **no real
> cardholder data** and **cannot authorize any transaction**. Every cryptogram,
> certificate and signature it returns is a recorded byte fixture, not computed
> cryptography. Use it to learn EMV and to test the robustness of **your own**
> readers — never against payment infrastructure you do not own, and never with
> a real card's data.

---

## 1. What this app is and why it exists

### 1.1 The problem it solves

A contactless (NFC) payment looks like magic: tap a card, the terminal beeps,
money moves. Underneath it is a strict interrogation — the terminal asks up to
~10 structured questions and the card must answer each one with byte-exact data
in milliseconds. If you want to **understand** that dialogue, or **verify that
a reader you built handles edge cases** (long responses, malformed lengths,
unknown commands) without crashing, you need a card you fully control. Real
cards are black boxes sealed with issuer private keys you will never see. This
app is the opposite: a glass-box card running on an Android phone, where every
answer is visible in source code and in the on-screen log.

### 1.2 What it is

An Android **Host Card Emulation (HCE)** application: the phone's NFC
controller routes incoming contactless APDUs (Application Protocol Data Units —
the request/response envelopes of smartcard communication) to an Android
`Service` instead of to a physical secure element. That service inspects each
Command APDU and returns a Response APDU, exactly as a plastic card's chip
would — except the answers come from test fixtures in code.

### 1.3 What it is not

- Not a payment instrument. It cannot pay, cannot be charged, cannot complete
  a real authorization. Terminals pursuing a genuine online approval will
  decline or abort — that is expected and correct.
- Not a cloner. It cannot copy a real card: it never sees one, and the key
  material that makes real cards unforgeable (issuer private keys) cannot be
  extracted from them by design.
- Not a shortcut around payment security. The responses are static recordings
  with a live transaction counter; nothing here generates valid dynamic
  cryptograms.

### 1.4 Who it is for

- **Students of EMV** who want to watch a full SELECT → GPO → READ → GENERATE AC
  conversation unfold live, with every byte explained.
- **Reader/POS developers** who need a deterministic, slightly adversarial
  counterpart while debugging their terminal firmware.
- **Security learners** studying the public research behind the lab features
  (see `docs/research/README.md`) on hardware they own.

---

## 2. How contactless EMV works (the 10-minute version)

Skip this if you know EMV; everything below maps 1:1 to log lines the app shows.

### 2.1 The cast

- **Terminal / reader / POS**: asks questions. In our lab setup this is the
  [TalkToYourCreditCard](https://github.com/AndroidCrypto/TalkToYourCreditCardG8)
  app on a second phone, or a USB NFC reader, or a real POS.
- **Card**: answers questions. That is this app (or a plastic card).
- **C-APDU / R-APDU**: the envelopes. A Command APDU is
  `CLA INS P1 P2 [Lc DATA] [Le]` — class, instruction, two parameters,
  optional length + payload, optional expected-response-length. A Response
  APDU is `DATA + SW1 SW2` — payload plus a two-byte status word
  (`9000` = success, `6A82` = file/record not found, `6D00` = instruction not
  supported, `61xx` = "I have `xx` more bytes, ask with GET RESPONSE").

### 2.2 The interrogation, step by step

Each step below shows the real bytes from the Visa trace in this repo
(`Sample_Visa_Card_Reader_Logfile.md`), what they mean, and what this app does.

**Step 1 — SELECT PPSE** (`00 A4 04 00 0E "2PAY.SYS.DDF01" 00`).
"Who lives here?" The reader selects the well-known Payment System Environment
directory present on every contactless card. The card answers with an FCI
(File Control Information) listing its applications. Ours advertises the
profile's AID (e.g. Visa `A0000000031010`) so the reader knows what to select
next.

**Step 2 — SELECT AID** (`00 A4 04 00 07 A0000000031010 00`).
"You — speak." The reader picks one application. The card answers with its
dossier: application label ("VISA DEBIT"), the **PDOL** (Processing Options
Data Object List — the exact shopping list of terminal data the card demands:
amount, date, unpredictable number…), language preference, and proprietary
discretionary data. The PDOL is the contract that makes step 3 possible.

**Step 3 — GET PROCESSING OPTIONS** (`80 A8 00 00 Lc <PDOL values> 00`).
"Here is everything on your shopping list — now what?" The reader submits the
PDOL values, crucially including the **unpredictable number (UN, tag 9F37)** —
fresh randomness binding this tap to this moment — plus amount, date, terminal
type. The card answers with the **AIP** (Application Interchange Profile: what
the card can do) and the **AFL** (Application File Locator: which records to
read next). Our app additionally **echoes the reader's UN into tag 9F26** and
**increments the ATC** (Application Transaction Counter, tag 9F36) — the two
behaviors that make a replay look alive in a reader log. A real card would also
compute session keys here; we replay recorded bytes, which is why no real
terminal will approve.

**Steps 4–7 — READ RECORD** (`00 B2 <rec> <sfi<<3|4> 00`).
"Show me your papers." The AFL points at files; the reader reads them one by
one. Records carry the PAN (tag 5A — ours is always a test PAN), expiry
(5F24), track-2 equivalent (57), cardholder name (5F20), CDOLs (what data a
GENERATE AC must include), and the ICC public-key certificate chain (9F46…).
Static replays, served from per-profile maps keyed `SFI/record`.

**Step 8 — GENERATE AC** (`80 AE <type> 00 Lc <CDOL values>`).
"Commit to this transaction." The reader submits CDOL data and requests a
cryptogram type (AAC = decline, TC = approve offline, ARQC = go online). A
real card computes an AES/DES-based cryptogram with its private key. We return
a static template fixture — the honest limit of a keyless emulator, and the
reason business terminals stop here.

**Step 9 — GET DATA** (`80 CA <tag-high> <tag-low> 00`).
"One more thing." The reader pulls individual objects (ATC 9F36, PIN try
counter 9F17…). Our ATC answer is **live** — it always reflects the session
counter, so cross-checking GPO's 9F36 against GET DATA's 9F36 is a built-in
self-test of the session state.

**Throughout — GET RESPONSE** (`00 C0 00 00 Le`).
"And the rest?" Whenever a response exceeds the first-chunk budget, we answer
`61xx` and the reader fetches the remainder with GET RESPONSE. The pending
bytes live in session state and are cleared on deactivation.

**End of tap — `onDeactivated`.** Field lost: phones separated, transaction
done or aborted. We reset ATC to the profile default, forget the last UN, and
drop chained bytes, so the next tap starts clean. Watching the ATC restart is
how you verify the reset works.

### 2.3 TLV — the language everything is written in

Every EMV payload is **BER-TLV**: Tag, Length, Value, recursively nestable.
`5A 08 4111111111111111` = tag 5A (PAN), length 8, value 8 BCD bytes.
`77 81 C6 …` = template 77, long-form length 0xC6. The app's log appends a
one-line summary to each response, e.g. `77[198]{82[2] 57[19] 9F36[2]}` —
template 77 of 198 bytes containing tags 82 (2B), 57 (19B), 9F36 (2B)… Reading
these summaries is the fastest way to learn TLV: tap, read the summary, find
the bytes in the hex, repeat.

### 2.4 Why a replay can never pay

Three independent walls: (1) the **ATC/cryptogram** — real terminals verify the
cryptogram online with the issuer, and ours is a recording; (2) the **ICC
private key** — signatures over dynamic data require a key burned into the
real chip at manufacture, unextractable by design; (3) the **UN binding** — our
echo is decorative pattern-matching, not a keyed MAC. Any one of these is
fatal to a real authorization; all three hold here.

---

## 3. Feature reference

### 3.1 APDU engine (`EmvCardEmulatorCore.java`)

The heart of the app, and deliberately **pure JVM** (zero Android imports) so
it compiles with plain `javac` and is unit-tested without a device. It parses
ISO 7816-4 cases 1–4, short and extended length (`Lc=0` + 2-byte length), and
dispatches on the header fields rather than memorizing whole commands — so any
reader's amount, date, or UN is accepted, not just the recorded trace's.
Suspicious lengths (Lc claiming more bytes than the APDU holds, Lc > 256
without extended-length framing) are flagged in the log instead of crashing.
SELECT payloads route per-AID: PPSE directory name vs Visa / Mastercard /
Amex (`A000000025`) / Discover (`A000000152`) prefixes. GPO responses are built
by TLV-tag lookup (find 9F36/9F26/9F62 wherever they nest, patch values
in place), never by hardcoded offsets.

### 3.2 The six card profiles

The profile switcher (radio group on the main screen) enables exactly one HCE
service at a time via `PackageManager.setComponentEnabledSetting` — Android
then routes taps only to that service. **After switching, re-select the app
under Settings → NFC → Tap and Pay** (Android caches the default).

- **Visa** (`A0000000031010`, test PAN `4111111111111111`): the richest trace —
  full GPO template with AIP/AFL/track-2, PDOL-driven UN echo (real 9F38 from
  the SELECT FCI), AFL-validated READ records (SFI 2, rec 3–6 — AFL byte `0x10`;
  the sample log labels this SFI 10, the pre-shift P1/P2 byte), first + second
  GENERATE AC templates (CDOL1/CDOL2), dynamic ATC from `0x03AA`.
- **Mastercard** (`A0000000041010`, test PAN `5555555555554444`): records on
  wire SFI 1/2/4 (sample log labels SFI 8/10/20, the pre-shift P2 bytes),
  null-PDOL GPO path (short `7722…` template with dynamic ATC), ATC from `0x0001`.
- **Amex** (`A000000025`, test PAN `378282246310005`): minimal 15-digit-PAN
  profile (tag 5A BCD with `F` pad nibble), records SFI 1 rec 1–2.
- **Discover** (`A000000152`, test PAN `6011111111111117`): tag 5A + track-2
  equivalent with test expiry/service code, records SFI 1 rec 1–2.
- **Basic responder**: answers `9000` to everything (or lab payloads, §3.5).
  PPSE-only AID filter, category `other`. The "is the plumbing working?" profile.
- **Imported card**: data-driven service answering from a JSON profile
  (§3.3) with live ATC on GPO and honest `6A82` for unmapped commands.

### 3.3 JSON card import + on-device editor (`EmvCardProfile` + `CardProfileStore`)

A profile is `{"label", "aid", "entries": [{"command", "response",
"prefixMatch"}]}` — an ordered C-APDU→R-APDU map. Exact match wins first;
`prefixMatch: true` entries (used for GPO `80a8`, whose PDOL data changes per
transaction) match by prefix. Files live in app-internal storage (no
permissions), the active file is remembered in `SharedPreferences`, and a
bundled sample Visa means the Imported profile works out of the box. Import
via the system file picker (JSON ≤ 1 MB, validated before storing); delete
with confirmation. The **Edit pairs** button opens the on-device editor
(`ProfileEditorActivity`): entry list with add/edit/delete dialogs plus a
label/AID dialog, validated by `EmvCardProfile.validateEntry/validateAid`
(even-length hex, 4-byte command minimum with an `80a8` GPO-prefix exception,
no trailing `9000` in responses — the service appends SW at tap time, storing
it would double-append — AID 5-16 bytes). Saves go through
`CardProfileStore.save`, and the Imported service re-reads the file on every
tap, so edits are live on the next tap. **Import rule: test captures only —
never a real card.**

### 3.4 Reader policy: strict vs lenient (`BaseHceEmulationService` + Lab card)

Two checkboxes on the Lab card control how card-like the fixture behaves on
every tap (read from SharedPreferences per C-APDU, defaults off = lenient lab
mode):

- **Strict AFL** (`strict_afl`): out-of-AFL READ RECORDs are declined `6A83`
  like a real card. Lenient mode serves them from the fixture and flags
  `afl=NOT-LISTED` in the log — friendlier for readers that probe extra records.
- **Strict length** (`strict_length`): GPO/GENERATE AC whose values length
  differs from the captured PDOL/CDOL contract is declined `6700`. Lenient mode
  serves the template and logs `pdol=MISMATCH` / `cdol1=MISMATCH` with expected
  vs actual byte counts.

Use lenient mode for first contact with an unknown reader (maximum
compatibility, mismatches visible in the log); flip strict mode on to verify
the reader follows the contracts the fixture advertised.

### 3.5 Tap export: pcap-style conversation files (`TapExport`)

Every tap is recorded as raw C-APDU/R-APDU pairs: the buffer opens at SELECT
PPSE and is written to `tap_<timestamp>.apdu` in internal storage on
`onDeactivated` (the log line tells you the filename). One exchange per line —
`C:<hex> R:<hex>` with SW included in R — `#` lines are comments
(scheme, pair count). The **Share tap export (.apdu)** button under the log
shares the most recent file as text; the format parses with a one-liner (skip
`#`, split on the space, strip `C:`/`R:`), and `TapExport.parse` round-trips it
(`TapExportTest`). Cap: 500 pairs per tap so a hostile reader can't grow
storage. Use it to diff taps across policy settings, or to feed captures into
the loopback harness as regression vectors.

### 3.6 Session log, file log, sharing (`MainActivity` + `FileLog`)

Every tap event is broadcast from the services (`HceCcEmulatorService` intent)
and rendered with a short timestamp, capped at 300 lines (a deque drops the
oldest — long sessions can't grow memory). In parallel, `FileLog` appends the
same lines to a per-launch session file in internal storage, so the full tap
history survives rotation and restarts. Copy puts the log on the clipboard,
Share sends it as text, Clear resets the view. The log opens with the
research-use notice and the session filename.

### 3.7 Lab mode — robustness-test your own reader (`LabPayload`, `LabProbe`, Basic service)

Background (see `docs/research/README.md`): public research ("Contactless
Overflow", IOActive 2023) showed NFC payment readers with stack buffer
overflows reachable through extended-length APDU responses. Vendors were
notified and patched; these fixtures let you **verify your own lab readers**
handle long and malformed responses gracefully. A phone doing HCE can deliver
responses a capped USB reader (e.g. ACR122U, 0xFF limit) cannot.

- **Long response**: Basic profile answers every command with `N` bytes of a
  chosen pattern + `9000`. Start at 256, raise stepwise.
- **Auto sweep**: each new tap session (detected by SELECT PPSE) steps through
  256 → 512 → … → 65535 bytes automatically — one tap series covers the range
  hands-free.
- **Malformed probes**: 8 cases cycling per tap where the declared `82 XX XX`
  length disagrees with what is actually sent (declare-64k-send-512,
  nested-inner-overflow, 3-byte `83` long form, declare-512-send-0, plus the
  exact 0x138/0x139 boundary pair from the paper and a well-formed baseline).
- **Reader dwell**: `onDeactivated` reports milliseconds between our last
  response and field loss — an instant drop after a big/malformed step hints
  the reader choked rather than processing normally.

Scope warning, repeated in-app: **your own hardware only.** A crash means the
reader mishandles extended APDUs — report it to the vendor, don't weaponize it.

### 3.8 TLV inspector (`TlvUtils`)

A small BER-TLV reader (multi-byte tags, short/long-form lengths, recursion
into constructed tags, never throws on malformed input) that appends compact
summaries to every logged response: `77[198]{82[2] 94[4] 57[19] …}`. It is the
fastest learning loop in the app — compare the summary against the hex until
TLV feels native.

### 3.9 NFC status, profile UI, Material3 layout

Status card (NFC missing / disabled / ready, checked on resume), profile radio
group with per-profile AID captions, imported-file card (active file, APDU
count, import/delete), lab card (enabled only for Basic), session-log card
(monospace, auto-scrolls to newest). Research notice is logged at startup.

---

## 4. How everything fits together (code tour)

```text
Reader tap
  → Android NFC → exactly one enabled HostApduService
      Visa/MC/Amex/Discover extend BaseHceEmulationService
        → EmvCardEmulatorCore.parse()          # header dispatch
        → routeSelect() / GPO builder / record map / AC template / GET DATA
        → maybeChain() → 61xx or 9000          # GET RESPONSE serves the rest
        → LocalBroadcastManager + FileLog      # screen log + session file
      Basic → 9000 or LabPayload/LabProbe      # robustness fixtures
      Imported → EmvCardProfile.findResponse() # JSON map + live ATC
  → onDeactivated → session reset (ATC, UN, chained bytes)
```

Key files: `EmvCardEmulatorCore.java` (pure-JVM core), `BaseHceEmulationService.java`
(shared dispatch/session), `HceCcEmulationService{ Visa, Mastercard, Amex,
Discover, Basic, Imported }.java`, `EmvCardProfile.java`/`CardProfileStore.java`
(import), `TlvUtils.java`, `LabPayload.java`/`LabProbe.java`, `FileLog.java`,
`MainActivity.java`, `res/xml/apduservice_*.xml` (one per profile) +
`AndroidManifest.xml` (Visa enabled by default, rest toggled by the UI).

---

## 5. Real-world scenarios

**A. Learn EMV end-to-end (30 min).** Visa profile → tap with
TalkToYourCreditCard → follow PPSE/AID/GPO/reads/AC in the log; match each TLV
summary to its hex. Then re-tap and watch ATC increment and reset.

**B. Bring up a reader firmware.** Point your firmware at the Basic profile
first (does SELECT route at all?), then Visa (does the full Q&A parse?), then
the 9F36 cross-check (GPO ATC == GET DATA ATC?). Use imported JSON to replay
yesterday's failing trace deterministically.

**C. Verify your reader's length handling.** Basic + long response from 256B
upward; then auto-sweep; then malformed probes. Instant-dwell + silence after
a probe step = mishandled length → vendor ticket, with the session file
attached.

**D. Regression-test the emulator itself.** `EmvLoopbackHarnessTest` replays
the whole conversation on JVM (see `LOOPBACK_HARNESS.md`) — 40 unit tests run
in seconds with no hardware.

---

## 6. Build, test, install

```bash
export ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk
./gradlew :app:testDebugUnitTest assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

`EmvCardEmulatorCore` also compiles standalone (no Android deps):
`javac -d /tmp/emv-core app/src/main/java/.../EmvCardEmulatorCore.java`.

---

## 7. Troubleshooting

HCE's classic frustrations, in order: (1) device has NFC but no HCE → different
device; (2) NFC off → Settings → Connections; (3) rival HCE apps stealing
SELECT PPSE → keep only this app enabled; (4) manifest/XML/AID mismatch — each
service needs `BIND_NFC_SERVICE` + `HOST_APDU_SERVICE` + `DEFAULT` category and
an XML listing PPSE `325041592E5359532E4444463031` + its AID; (5) default lost
after reinstall → re-select under Tap and Pay, and reinstall (not re-run) after
renaming a service class; (6) business terminal aborts mid-flow → expected for
replayed cryptograms, use TalkToYourCreditCard for first tests.

## 8. Future development plan

Done since the last roadmap review: PDOL-driven GPO (real 9F38 captured from
the SELECT FCI, UN located field-by-field), CDOL1/CDOL2 collection from record
data with 1st/2nd GENERATE AC routing, AFL-driven READ validation (from tag
94), explicit MagStripe `80 2A 8E 80` decline (`6985`), per-APDU length-contract
logging (PDOL/AFL/CDOL match vs `MISMATCH`), strict AFL mode (`strictAfl`
flag → out-of-AFL reads declined `6A83`), PDOL/CDOL length policy (`LENIENT`
default vs `STRICT` → `6700`), cryptogram-type logging (ARQC/TC/AAC from P1),
per-scheme golden-trace tests (`EmvGoldenTraceTest`: full tap per profile).
Fixed along the way: Mastercard record keys now use wire SFI numbering
(P2≫3) matching the GPO AFL; the Mastercard GPO template advertises the real
3-entry AFL from the sample reader log.

Near term: done — on-device policy toggles (Strict AFL → `6A83`, Strict length →
`6700`, Lab card checkboxes, read per-tap from SharedPreferences).
Medium term: done — profile editor UI (`ProfileEditorActivity`: on-device
label/AID/APDU-pair editing with `validateEntry`/`validateAid` rules, live on
next tap). Done: parser fuzzing with
the LabProbe corpus both directions (`EmvParserFuzzTest`: deterministic seed,
never-throws + truncation-flagging); pcap-style tap export (`TapExport`:
per-tap `C:/R:` conversation files + share button + `TapExportTest`).
Non-goals, permanently: real cryptogram computation, real PAN support, anything
authorizable.

## 9. License & sources

See `LICENSE`. Tutorial: AndroidCrypto (Medium). Reader app:
[TalkToYourCreditCardG8](https://github.com/AndroidCrypto/TalkToYourCreditCardG8).
Research papers in `docs/research/` belong to their authors, referenced for
defensive testing only.

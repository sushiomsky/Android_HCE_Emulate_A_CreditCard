# Firmware Patching Roadmap (defensive)

Goal: take a reader that fails this app's length/probe tests from *vulnerable*
to *verified fixed*, through vendor channels, with the app as the regression
harness. Scope is strictly readers you own or are contracted to assess.

## Phase 0 — Authorization (gate for everything below)

- Written permission from the device owner covering NFC robustness testing,
  firmware extraction/analysis, and patch validation.
- If third-party hardware: rules of engagement, disclosure policy, data
  handling for any captured traces (no real PANs — lab test cards only).
- No authorization → stop. Nothing below is attempted.

## Phase 1 — Inventory (app-supported today)

- Tap each reader with an EMV profile; the app captures the terminal
  fingerprint automatically (GPO PDOL: IFD serial, terminal ID, type, caps).
- Record model + firmware from the reader display/sticker in the Reader card.
- Output: `reader_db.json` = fleet list with firmware versions and per-step
  outcomes. This is the patch backlog.

## Phase 2 — Firmware acquisition

- Only from legitimate sources: vendor support portals, signed update
  packages for your own devices, JTAG/dump of your own units where the
  vendor permits it.
- Never redistribute vendor firmware (license + copyright). The repo stores
  fingerprints and test results, never binaries.
- Record image version/hash alongside the reader DB entry for traceability.

## Phase 3 — Lab analysis (your bench, not the phone)

- Identify the APDU/response parser and its length handling; confirm which
  probe case from the app maps to the fault (declared-vs-received confusion,
  nested-TLV over-read, long-form lengths).
- Deliverable per device: fault note (parser location, trigger shape,
  observed behavior) — stored as analyst notes, not exploit code.

## Phase 4 — Patch

- Preferred route: vendor patch. Send the fault note + tap exports as
  evidence through the vendor's security contact; track the ticket in the
  reader DB entry.
- Own-patch route (only where you hold the signing rights / vendor
  authorizes custom firmware): minimal bounds/length validation at the
  parser boundary, no behavior changes elsewhere.
- Every patch gets a version bump recorded in the DB.

## Phase 5 — Verification with this app (regression suite)

- Re-run the identical sweep + probe series against the patched unit:
  same steps, same order (probe index resets per enable).
- Pass criteria: no ANOMALY verdicts, dwell times back at baseline, reader
  processes or cleanly declines every step.
- Keep before/after session files + `.apdu` tap exports as the evidence
  pack attached to the ticket/DB entry.

## Phase 6 — Coordinated disclosure & rollout

- Confirm the vendor's fix covers the reported trigger shapes; re-test the
  vendor-supplied image before fleet rollout.
- Public notes only after the vendor ships and affected users can update
  (the Contactless Overflow disclosure timeline is the reference model).

## Phase 7 — Fleet close-out

- Mark each DB entry fixed with the verified firmware version; keep the
  evidence pack. Re-sweep on every future firmware update (regressions
  happen — that is exactly what the one-tap series is for).

## Explicitly out of scope

- Firmware redistribution, exploit development, bypassing secure boot or
  signature checks, testing hardware without authorization. Anything in this
  list is a stop-work item, not a roadmap item.

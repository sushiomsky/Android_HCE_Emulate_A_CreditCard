# Research papers

Background reading that shaped this app's lab features. All documents are used
for **defensive testing of your own hardware only**.

| File | Source | Why it matters here |
|---|---|---|
| `androidcrypto-hce-emulate-credit-card.pdf` | AndroidCrypto tutorial (Medium, Oct 2024) | The tutorial this repo implements: PPSE → Select AID → GPO → Read Records Q&A, static replay approach. |
| `blackhat2015-crash-and-pay-contactless.pdf` | Fillmore, Black Hat USA 2015 | Contactless EMV/MagStripe flows, BER-TLV + APDU reference. Basis for the in-app TLV summary lines and the explicit MagStripe CCC (`80 2A 8E 80`) handling. |
| `ioactive-contactless-overflow-nfc.pdf` | Rodriguez, IOActive 2023 | Stack overflows in payment readers via extended-length APDUs (`82 XX XX`, up to 0xFFFF). Basis for the Lab oversized-response + auto-sweep feature. All vendors patched; use to verify your own readers. |
| `blackhat2013-rooting-sim-cards.pdf` | Nohl / SRLabs, Black Hat USA 2013 | OTA DES key cracking, downgrade attacks, Java sandbox escapes on smartcards. Lesson applied: never trust static replayed crypto — our responses carry no valid cryptograms and must never be mistaken for real transactions. |

Key takeaways applied in code:
- Responses are static replays with a live ATC only; cryptograms/CVC3 are recorded
  bytes, not computed values (cf. Crash & Pay on dynamic CVC generation).
- Unknown/dynamic commands get explicit status words (`6A82`/`6985`), never a
  misleading `9000`, so reader logs show exactly what is unimplemented.
- Length handling is tested explicitly (Lab sweep) because parsers that trust
  length fields are the recurring bug class (Contactless Overflow).

# docx-injection-scan

Finds instructions hidden in Office documents that are aimed at an AI assistant
rather than at the person reading the file.

```bash
bun scan.ts report.docx                 # one file
bun scan.ts ~/Downloads --recursive     # a tree
bun scan.ts ~/Downloads --json          # machine-readable

bun watch.ts <folder> --quarantine <dir>   # auto-quarantine on arrival
bun watch.ts <folder> --dry-run            # log only, move nothing

bun make-test-docx.ts && bun test.ts       # regenerate corpus, run regressions
```

Exit code 1 means findings, so it gates a pipeline directly.

Requires [Bun](https://bun.sh). No dependencies, no external commands, no network
calls: the zip container is parsed directly, so it behaves identically on
Windows, macOS, and Linux, and it never sends a document anywhere.

## Two layers, deliberately unequal

**Layer 1, HIGH severity, language-independent.** Text the file itself declares
unreadable: colour matched to its background (any colour, not just white),
sub-2pt type, the hidden-text flag, glyphs scaled to 1%, paragraphs pushed off
the page, zero-width characters, or a carrier no reader opens (alt text, document
properties, headers, footers, footnotes, comments, embedded XML).

This layer never reads the language. Translating the payload, rewriting it,
or encoding it changes nothing, because the signal is the concealment, not
the words. That is what makes it the load-bearing layer.

**Layer 2, MEDIUM severity, language-dependent.** What the text actually says:
override phrasing, concealment instructions, role reassignment, chat delimiters,
conditional triggers, outbound-data instructions, across fourteen languages, with
confusable-letter folding and letter-spacing collapse. Promoted to HIGH only when
it appears inside layer-1 hidden content.

Layer 2 is supporting evidence and always will be. Wording and language are free
for an attacker to change; visibility is not.

## Verified coverage

Every row has a generated test document and a regression assertion.

| Technique | Caught by | Test case |
| --- | --- | --- |
| White on white | colour vs background | `01` |
| Foreign language payload | formatting + per-language phrases | `02` `03` `04` |
| Cyrillic lookalike letters | formatting + confusable folding | `05` |
| Zero-width characters between letters | formatting + invisible-char check | `06` |
| Payload in image alt text | carrier visibility | `07` |
| Payload in header or footer | carrier visibility | `08` |
| Payload in document properties | carrier visibility | `09` |
| Base64-encoded payload | formatting + encoded-blob check | `10` |
| Text matching a dark table cell fill | colour vs resolved background | `11` |
| Glyphs scaled to 1% width | character-scale check | `12` |
| Paragraph pushed off the page | indent and frame check | `13` |
| Hidden text with no keywords at all | formatting alone | `14` |
| Injection wording in plainly visible text | reported MEDIUM, not HIGH | `15` |
| Unicode Tags payload in normal black text | tag-block decode | `16` |
| Stacked variation selectors (steganography) | selector-run check | `17` |

## Known gaps

Honest list, because a scanner that overstates its coverage is worse than none.

- **Text inside images.** No OCR. A payload rendered as a picture is invisible to
  this tool while remaining readable to a vision-capable model.
- **Encrypted or password-protected files.** Reported as uninspectable rather
  than clean. That is the correct answer, but it is not detection.
- **Legacy binary `.doc` and `.rtf`.** Detected as uninspectable, not parsed.
- **`.xlsx` and `.pptx`.** Accepted by the CLI but only the shared parts are
  understood; cell-level and slide-level formatting is not yet resolved.
- **Split across multiple files.** Each fragment can look innocuous alone and
  assemble only inside the assistant's context window. Per-file scanning cannot
  see that by construction.
- **External content.** A document that merely links somewhere, with the payload
  living at the far end, has nothing to detect locally.

## Purview

`purview/ai-injection-sit.xml` is a custom sensitive information type
implementing layer 2 tenant-wide. `purview/DEPLOY.md` is the runbook, including
why two of the test documents are expected to be missed at that layer.

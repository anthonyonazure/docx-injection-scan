/**
 * Detection core.
 *
 * Two independent layers, deliberately unequal in weight:
 *
 *   Layer 1 (HIGH, language-independent) - text the file itself declares to be
 *   unreadable: colour matched to its background, sub-2pt sizing, hidden flags,
 *   zero-scale glyphs, off-canvas placement, or a carrier a reader never opens
 *   (alt text, metadata, footnotes, headers). None of this depends on knowing
 *   what the text says, so translating the payload changes nothing.
 *
 *   Layer 2 (MEDIUM, language-dependent) - what the text says. Supporting
 *   evidence only, since wording and language are free for the attacker to change.
 */
import { matchPhrases, scriptsUsed, findEncodedBlobs, decodeTagChars, INVISIBLE_CHARS, VARIATION_SELECTOR_RUN } from "./patterns.ts";
import { listEntries, readEntry, type ZipEntry } from "./zip.ts";

export type Severity = "high" | "medium" | "low";

export type Finding = {
  severity: Severity;
  reason: string;
  detail: string;
  where: string;
  text: string;
};

export type ScanResult = {
  file: string;
  findings: Finding[];
  visibleChars: number;
  hiddenChars: number;
  error?: string;
};

/** Parts that carry text a reader may never look at, with how visible each is. */
const PART_VISIBILITY: Array<[RegExp, string, boolean]> = [
  [/^word\/document\.xml$/, "body", true],
  [/^word\/header\d*\.xml$/, "header", false],
  [/^word\/footer\d*\.xml$/, "footer", false],
  [/^word\/footnotes\.xml$/, "footnote", false],
  [/^word\/endnotes\.xml$/, "endnote", false],
  [/^word\/comments\.xml$/, "comment", false],
  [/^word\/(commentsExtended|commentsIds)\.xml$/, "comment metadata", false],
  [/^word\/glossary\/document\.xml$/, "glossary / building blocks", false],
  [/^docProps\/core\.xml$/, "document properties", false],
  [/^docProps\/app\.xml$/, "document properties", false],
  [/^docProps\/custom\.xml$/, "custom properties", false],
  [/^customXml\/item\d*\.xml$/, "embedded custom XML", false],
];

/** One open container: the file bytes plus its parsed directory. */
type Container = { buf: Buffer; entries: ZipEntry[] };

async function openContainer(path: string): Promise<Container> {
  const buf = Buffer.from(await Bun.file(path).arrayBuffer());
  return { buf, entries: listEntries(buf) };
}

function readPart(container: Container, name: string): string {
  const entry = container.entries.find((e) => e.name === name);
  if (!entry) return "";
  return readEntry(container.buf, entry)?.toString("utf8") ?? "";
}

function decodeEntities(s: string): string {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}

function stripTags(s: string): string {
  return decodeEntities(s.replace(/<[^>]+>/g, ""));
}

type Rgb = [number, number, number];

function parseColor(hex: string | null | undefined): Rgb | null {
  if (!hex) return null;
  const m = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function luminance([r, g, b]: Rgb): number {
  return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
}

function distance(a: Rgb, b: Rgb): number {
  return Math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2);
}

/** Ranges of every table cell, innermost-last, with the cell's fill colour. */
function cellRanges(xml: string): Array<{ start: number; end: number; fill: string | null }> {
  const ranges: Array<{ start: number; end: number; fill: string | null }> = [];
  const stack: number[] = [];
  const tagRe = /<(\/?)w:tc(?:\s[^>]*)?>/g;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(xml))) {
    if (m[1] === "/") {
      const start = stack.pop();
      if (start === undefined) continue;
      const inner = xml.slice(start, m.index);
      const props = inner.match(/<w:tcPr>[\s\S]*?<\/w:tcPr>/)?.[0] ?? "";
      ranges.push({ start, end: m.index, fill: props.match(/<w:shd[^>]*w:fill="([^"]+)"/)?.[1] ?? null });
    } else if (!m[0].endsWith("/>")) {
      stack.push(m.index);
    }
  }
  return ranges;
}

type RunInfo = {
  text: string;
  where: string;
  hidden: boolean;
  hiddenReasons: Array<{ reason: string; detail: string }>;
};

/**
 * Walks paragraphs and their runs, resolving the background each run sits on
 * (page, paragraph shading, or enclosing table cell) so "invisible" means
 * "matches whatever is behind it", not just "white".
 */
function analyzeRuns(xml: string, partLabel: string, readerVisible: boolean): RunInfo[] {
  const cells = cellRanges(xml);
  const out: RunInfo[] = [];
  const paraRe = /<w:p(?:\s[^>]*)?>[\s\S]*?<\/w:p>/g;
  let p: RegExpExecArray | null;

  while ((p = paraRe.exec(xml))) {
    const para = p[0];
    const paraStart = p.index;
    const pPr = para.match(/<w:pPr>[\s\S]*?<\/w:pPr>/)?.[0] ?? "";

    const enclosing = cells
      .filter((c) => paraStart > c.start && paraStart < c.end)
      .sort((a, b) => b.start - a.start)[0];

    const bgHex = pPr.match(/<w:shd[^>]*w:fill="([^"]+)"/)?.[1] ?? enclosing?.fill ?? null;
    const background = parseColor(bgHex === "auto" ? "FFFFFF" : bgHex) ?? [255, 255, 255];

    // Paragraph pushed outside the printable page.
    const indent = Number(pPr.match(/<w:ind[^>]*w:left="(-?\d+)"/)?.[1] ?? 0);
    const frameX = Number(pPr.match(/<w:framePr[^>]*w:x="(-?\d+)"/)?.[1] ?? 0);
    const offCanvas = indent < -2000 || frameX < -2000;

    for (const run of para.match(/<w:r(?:\s[^>]*)?>[\s\S]*?<\/w:r>/g) ?? []) {
      const text = decodeEntities(
        (run.match(/<w:t(?:\s[^>]*)?>[\s\S]*?<\/w:t>/g) ?? []).map(stripTags).join("")
      );
      if (!text.trim()) continue;

      const rPr = run.match(/<w:rPr>[\s\S]*?<\/w:rPr>/)?.[0] ?? "";
      const reasons: Array<{ reason: string; detail: string }> = [];

      const runBgHex = rPr.match(/<w:shd[^>]*w:fill="([^"]+)"/)?.[1];
      const bg = parseColor(runBgHex === "auto" ? "FFFFFF" : runBgHex) ?? background;

      const colorHex = rPr.match(/<w:color[^>]*w:val="([^"]+)"/)?.[1] ?? null;
      const color = colorHex && colorHex !== "auto" ? parseColor(colorHex) : [0, 0, 0] as Rgb;
      if (color && distance(color, bg) < 40) {
        reasons.push({
          reason: "text colour matches its background",
          detail: `#${colorHex ?? "auto"} on #${(bg.map((c) => c.toString(16).padStart(2, "0")).join("")).toUpperCase()}`,
        });
      }
      if (colorHex && colorHex !== "auto" && luminance(parseColor(colorHex)!) > 0.93 && luminance(bg) > 0.9) {
        // Covered above in most cases; kept for near-white on off-white pages.
      }

      const half = Number(rPr.match(/<w:sz[^>]*w:val="(\d+)"/)?.[1] ?? 0);
      if (half > 0 && half <= 4) reasons.push({ reason: "unreadable font size", detail: `${half / 2}pt` });

      if (/<w:vanish\s*\/?>/.test(rPr) && !/<w:vanish[^>]*w:val="(0|false)"/.test(rPr))
        reasons.push({ reason: "hidden-text attribute", detail: "w:vanish" });

      if (/<w:webHidden\s*\/?>/.test(rPr))
        reasons.push({ reason: "hidden in web view", detail: "w:webHidden" });

      const scale = Number(rPr.match(/<w:w[^>]*w:val="(\d+)"/)?.[1] ?? 100);
      if (scale > 0 && scale <= 10) reasons.push({ reason: "glyphs scaled to nothing", detail: `${scale}% width` });

      const pos = Number(rPr.match(/<w:position[^>]*w:val="(-?\d+)"/)?.[1] ?? 0);
      if (Math.abs(pos) > 200) reasons.push({ reason: "text shifted off the line", detail: `offset ${pos}` });

      if (offCanvas) reasons.push({ reason: "positioned outside the page", detail: `indent ${indent}, frame ${frameX}` });

      INVISIBLE_CHARS.lastIndex = 0;
      if (INVISIBLE_CHARS.test(text)) {
        INVISIBLE_CHARS.lastIndex = 0;
        reasons.push({ reason: "zero-width characters inside the text", detail: "invisible unicode" });
      }

      // Unicode Tags carry a full ASCII payload inside otherwise normal text.
      const smuggled = decodeTagChars(text);
      if (smuggled.length >= 12) {
        reasons.push({
          reason: "hidden payload encoded in Unicode Tags characters",
          detail: `${smuggled.length} characters decode to: "${smuggled.slice(0, 80)}"`,
        });
      }

      if (VARIATION_SELECTOR_RUN.test(text))
        reasons.push({ reason: "stacked variation selectors", detail: "steganographic encoding, not emoji styling" });

      out.push({
        text,
        where: partLabel,
        hidden: reasons.length > 0 || !readerVisible,
        hiddenReasons: reasons,
      });
    }
  }
  return out;
}

/** Alt text and object titles: read by every text extractor, seen by no reader. */
function altTexts(xml: string): string[] {
  const found: string[] = [];
  for (const attr of xml.match(/\b(descr|title|alt)="([^"]{12,})"/g) ?? []) {
    const value = decodeEntities(attr.replace(/^\w+="/, "").replace(/"$/, ""));
    if (value.trim()) found.push(value);
  }
  return found;
}

export async function scanDocx(path: string): Promise<ScanResult> {
  const result: ScanResult = { file: path, findings: [], visibleChars: 0, hiddenChars: 0 };
  const add = (f: Finding) => result.findings.push(f);

  let container: Container;
  let entries: string[];
  try {
    container = await openContainer(path);
    entries = container.entries.map((e) => e.name);
  } catch {
    // Not a zip: either legacy binary .doc/.rtf, or an encrypted OOXML wrapper.
    const head = new Uint8Array(await Bun.file(path).slice(0, 8).arrayBuffer());
    const magic = [...head].map((b) => b.toString(16).padStart(2, "0")).join("");
    const legacy = magic.startsWith("d0cf11e0");
    result.error = legacy
      ? "legacy or encrypted Office container (OLE) - text cannot be extracted or inspected"
      : "unreadable container - cannot be inspected";
    add({
      severity: "high",
      reason: "file cannot be inspected",
      detail: result.error,
      where: "container",
      text: "",
    });
    return result;
  }

  if (entries.some((e) => /^EncryptedPackage$/i.test(e) || /^EncryptionInfo$/i.test(e))) {
    add({
      severity: "high",
      reason: "file cannot be inspected",
      detail: "password-protected or encrypted package - contents are opaque to any scanner",
      where: "container",
      text: "",
    });
    return result;
  }

  const visibleText: string[] = [];
  const hiddenText: string[] = [];

  for (const entry of entries) {
    const match = PART_VISIBILITY.find(([re]) => re.test(entry));
    // Any other XML part under word/ that carries <w:t> still gets scanned.
    const isOtherWordXml = !match && /^word\/.*\.xml$/.test(entry) && !/^word\/(styles|settings|fontTable|theme|numbering|webSettings)/.test(entry);
    if (!match && !isOtherWordXml) continue;

    const [, label, readerVisible] = match ?? [null, `other part (${entry})`, false];
    const xml = readPart(container, entry);
    if (!xml) continue;

    if (/^docProps\//.test(entry) || /^customXml\//.test(entry)) {
      const text = stripTags(xml).replace(/\s+/g, " ").trim();
      if (text) {
        hiddenText.push(text);
        const hits = matchPhrases(text);
        for (const hit of hits) {
          add({
            severity: "high",
            reason: "instruction-shaped text in a non-visible carrier",
            detail: `${hit.label} (${hit.language}) inside ${label}`,
            where: label,
            text: hit.excerpt,
          });
        }
      }
      continue;
    }

    for (const alt of altTexts(xml)) {
      hiddenText.push(alt);
      const hits = matchPhrases(alt);
      const long = alt.length > 300;
      if (hits.length || long) {
        add({
          severity: hits.length ? "high" : "medium",
          reason: hits.length ? "instruction-shaped text in image alt text" : "unusually long image alt text",
          detail: hits.length ? hits.map((h) => `${h.label} (${h.language})`).join(", ") : `${alt.length} characters`,
          where: `${label} / alt text`,
          text: alt.slice(0, 140),
        });
      }
    }

    for (const run of analyzeRuns(xml, label, readerVisible)) {
      if (run.hiddenReasons.length) {
        hiddenText.push(run.text);
        result.hiddenChars += run.text.length;
        for (const r of run.hiddenReasons) {
          add({ severity: "high", reason: r.reason, detail: r.detail, where: run.where, text: run.text.trim().slice(0, 140) });
        }
      } else if (readerVisible) {
        visibleText.push(run.text);
        result.visibleChars += run.text.length;
      } else {
        // Text in a low-visibility carrier: only interesting if it reads like instructions.
        hiddenText.push(run.text);
        result.hiddenChars += run.text.length;
      }
    }
  }

  const hiddenJoined = hiddenText.join(" ");
  const visibleJoined = visibleText.join(" ");

  // Layer 2: what the text says. Weighted higher when it sits in hidden text.
  for (const hit of matchPhrases(hiddenJoined)) {
    add({
      severity: "high",
      reason: "instruction-shaped text in non-visible content",
      detail: `${hit.label} (${hit.language})`,
      where: "hidden content",
      text: hit.excerpt,
    });
  }
  for (const hit of matchPhrases(visibleJoined)) {
    add({
      severity: "medium",
      reason: "instruction-shaped text in visible content",
      detail: `${hit.label} (${hit.language})`,
      where: "body",
      text: hit.excerpt,
    });
  }

  // A payload translated into another script shows up as a script the rest of
  // the document never uses. Catches foreign-language payloads with no keyword match.
  if (hiddenJoined.trim().length > 40) {
    const visibleScripts = scriptsUsed(visibleJoined);
    const foreign = [...scriptsUsed(hiddenJoined)].filter((s) => !visibleScripts.has(s));
    if (foreign.length) {
      add({
        severity: "medium",
        reason: "hidden text uses a writing system the document never uses",
        detail: `${foreign.join(", ")} appears only in non-visible content`,
        where: "hidden content",
        text: hiddenJoined.slice(0, 140),
      });
    }
  }

  for (const blob of findEncodedBlobs(hiddenJoined)) {
    add({
      severity: "medium",
      reason: "encoded blob in non-visible content",
      detail: `${blob.length} characters of base64-like data`,
      where: "hidden content",
      text: `${blob.slice(0, 80)}...`,
    });
  }

  // Volume check: a page of invisible text is anomalous regardless of content.
  if (result.hiddenChars > 400 && result.hiddenChars > result.visibleChars * 0.25) {
    add({
      severity: "medium",
      reason: "large volume of non-visible text",
      detail: `${result.hiddenChars} hidden vs ${result.visibleChars} visible characters`,
      where: "document",
      text: "",
    });
  }

  const rank: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
  result.findings.sort((a, b) => rank[a.severity] - rank[b.severity]);
  return result;
}

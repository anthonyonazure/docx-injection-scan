#!/usr/bin/env bun
/**
 * Regression suite: every evasion technique in testdocs/ must be detected, and
 * the clean document must stay clean. Run after any change to the detector.
 *
 *   bun make-test-docx.ts && bun test.ts
 */
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { scanDocx } from "./src/detect.ts";

const DIR = join(import.meta.dir, "testdocs");

/** Case name -> what the detector must produce. */
const EXPECT: Record<string, { high: number; medium?: number; note: string }> = {
  "00-clean": { high: 0, medium: 0, note: "no findings at all" },
  "15-visible-prose-only": { high: 0, note: "visible text only, must not be treated as hidden" },
};

const files = (await readdir(DIR)).filter((f) => f.endsWith(".docx")).sort();
let failures = 0;

for (const name of files) {
  const key = name.replace(/\.docx$/, "");
  const r = await scanDocx(join(DIR, name));
  const high = r.findings.filter((f) => f.severity === "high").length;
  const medium = r.findings.filter((f) => f.severity === "medium").length;

  const expected = EXPECT[key];
  let ok: boolean;
  let why: string;

  if (expected) {
    ok = high === expected.high && (expected.medium === undefined || medium === expected.medium);
    why = expected.note;
  } else {
    // Every other case carries a real payload: at least one HIGH is required,
    // since a medium-only result would mean the language layer carried it alone.
    ok = high >= 1;
    why = "payload must trip a language-independent HIGH signal";
  }

  if (!ok) failures++;
  const langs = [...new Set(
    r.findings.map((f) => /\((\p{Ll}{2}|any)\)/u.exec(f.detail)?.[1]).filter(Boolean)
  )].join(",");

  console.log(
    `${ok ? "PASS" : "FAIL"}  ${key.padEnd(24)} high=${String(high).padEnd(2)} med=${String(medium).padEnd(2)}` +
    `${langs ? ` langs=${langs}` : ""}${ok ? "" : `  <-- ${why}`}`
  );
}

console.log(failures ? `\n${failures} of ${files.length} FAILED` : `\nall ${files.length} cases pass`);
process.exit(failures ? 1 : 0);

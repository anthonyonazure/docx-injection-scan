#!/usr/bin/env bun
/**
 * docx-injection-scan
 *
 * Flattens an Office document the way an AI assistant sees it and reports text a
 * human reader would never notice. Point it at files or folders.
 *
 *   bun scan.ts report.docx
 *   bun scan.ts ~/Downloads --recursive
 *   bun scan.ts ~/Downloads --json > findings.json
 *
 * Exit codes: 0 clean, 1 findings, 2 usage or unreadable input.
 */
import { readdir, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { scanDocx, type ScanResult } from "./src/detect.ts";

const SCANNABLE = new Set([".docx", ".docm", ".dotx", ".dotm", ".doc", ".xlsx", ".pptx"]);

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith("-")));
const inputs = argv.filter((a) => !a.startsWith("-"));
const asJson = flags.has("--json");
const recursive = flags.has("--recursive") || flags.has("-r");
const quiet = flags.has("--quiet") || flags.has("-q");

if (inputs.length === 0) {
  console.error("usage: bun scan.ts <file|folder> [...] [--recursive] [--json] [--quiet]");
  process.exit(2);
}

async function collect(target: string): Promise<string[]> {
  const info = await stat(target);
  if (info.isFile()) return SCANNABLE.has(extname(target).toLowerCase()) ? [target] : [];
  const found: string[] = [];
  for (const entry of await readdir(target, { withFileTypes: true })) {
    if (entry.name.startsWith("~$") || entry.name.startsWith(".")) continue;
    const full = join(target, entry.name);
    if (entry.isDirectory()) {
      if (recursive) found.push(...(await collect(full)));
    } else if (SCANNABLE.has(extname(entry.name).toLowerCase())) {
      found.push(full);
    }
  }
  return found;
}

const files: string[] = [];
for (const input of inputs) {
  try {
    files.push(...(await collect(input)));
  } catch (err) {
    console.error(`cannot read ${input}: ${(err as Error).message}`);
    process.exit(2);
  }
}

const results: ScanResult[] = [];
for (const file of files) results.push(await scanDocx(file));

if (asJson) {
  console.log(JSON.stringify(results, null, 2));
} else {
  for (const r of results) {
    if (r.findings.length === 0) {
      if (!quiet) console.log(`CLEAN  ${r.file}`);
      continue;
    }
    const high = r.findings.filter((f) => f.severity === "high").length;
    console.log(`\nFLAG   ${r.file}`);
    console.log(`       ${r.findings.length} finding(s), ${high} high`);
    for (const f of r.findings) {
      console.log(`  [${f.severity.toUpperCase().padEnd(6)}] ${f.reason}`);
      console.log(`           ${f.detail}  <${f.where}>`);
      if (f.text) console.log(`           "${f.text}"`);
    }
  }
  const flagged = results.filter((r) => r.findings.length).length;
  console.log(`\n${results.length} file(s) scanned, ${flagged} flagged.`);
}

process.exit(results.some((r) => r.findings.length) ? 1 : 0);

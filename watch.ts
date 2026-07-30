#!/usr/bin/env bun
/**
 * Folder watcher: scans documents as they arrive and quarantines the flagged ones
 * before anything indexes them.
 *
 *   bun watch.ts ~/Library/CloudStorage/OneDrive-Example/Shared
 *   bun watch.ts <folder> --quarantine ~/Quarantine --min high --dry-run
 *
 * Quarantine moves the file into a sibling folder and drops a .findings.json
 * beside it, so nothing is destroyed and every decision is auditable.
 */
import { watch } from "node:fs";
import { mkdir, rename, writeFile, stat } from "node:fs/promises";
import { join, basename, extname, resolve } from "node:path";
import { scanDocx } from "./src/detect.ts";

const argv = process.argv.slice(2);
const flags = argv.filter((a) => a.startsWith("--"));
const positional = argv.filter((a) => !a.startsWith("--"));
const target = positional[0];

function flagValue(name: string, fallback: string): string {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : fallback;
}

if (!target) {
  console.error("usage: bun watch.ts <folder> [--quarantine <dir>] [--min high|medium] [--dry-run]");
  process.exit(2);
}

const WATCH_DIR = resolve(target);
const QUARANTINE = resolve(flagValue("--quarantine", join(WATCH_DIR, "_quarantine")));
const MIN: "high" | "medium" = flagValue("--min", "high") === "medium" ? "medium" : "high";
const DRY_RUN = flags.includes("--dry-run");
const LOG = join(QUARANTINE, "scan-log.ndjson");

const SCANNABLE = new Set([".docx", ".docm", ".dotx", ".dotm", ".doc", ".xlsx", ".pptx"]);
const pending = new Map<string, ReturnType<typeof setTimeout>>();
const recentlyHandled = new Set<string>();

await mkdir(QUARANTINE, { recursive: true });

function stamp(): string {
  return new Date().toISOString();
}

async function log(entry: Record<string, unknown>) {
  await writeFile(LOG, `${JSON.stringify({ at: stamp(), ...entry })}\n`, { flag: "a" });
}

/** Waits for the file to stop growing, so a large sync-in-progress isn't scanned half-written. */
async function settled(path: string): Promise<boolean> {
  let last = -1;
  for (let i = 0; i < 10; i++) {
    let size: number;
    try {
      size = (await stat(path)).size;
    } catch {
      return false;
    }
    if (size === last && size > 0) return true;
    last = size;
    await Bun.sleep(400);
  }
  return true;
}

async function handle(path: string) {
  if (!SCANNABLE.has(extname(path).toLowerCase())) return;
  if (path.startsWith(QUARANTINE)) return;
  if (basename(path).startsWith("~$")) return;
  if (!(await settled(path))) return;

  let result;
  try {
    result = await scanDocx(path);
  } catch (err) {
    console.error(`${stamp()}  ERROR  ${path}: ${(err as Error).message}`);
    return;
  }

  const high = result.findings.filter((f) => f.severity === "high").length;
  const medium = result.findings.filter((f) => f.severity === "medium").length;
  const trips = MIN === "high" ? high > 0 : high + medium > 0;

  if (!trips) {
    console.log(`${stamp()}  CLEAN  ${basename(path)}`);
    await log({ file: path, verdict: "clean", high, medium });
    return;
  }

  console.log(`${stamp()}  FLAG   ${basename(path)}  (${high} high, ${medium} medium)`);
  for (const f of result.findings.slice(0, 5)) {
    console.log(`         [${f.severity}] ${f.reason} <${f.where}> ${f.detail}`);
  }

  if (DRY_RUN) {
    await log({ file: path, verdict: "flagged", action: "dry-run", high, medium, findings: result.findings });
    return;
  }

  const safeName = `${Date.now()}-${basename(path)}`;
  const dest = join(QUARANTINE, safeName);
  try {
    await rename(path, dest);
    await writeFile(`${dest}.findings.json`, JSON.stringify(result, null, 2));
    console.log(`         quarantined -> ${dest}`);
    await log({ file: path, verdict: "flagged", action: "quarantined", dest, high, medium, findings: result.findings });
  } catch (err) {
    console.error(`         quarantine FAILED: ${(err as Error).message}`);
    await log({ file: path, verdict: "flagged", action: "quarantine-failed", error: String(err), high, medium });
  }
}

function schedule(path: string) {
  if (recentlyHandled.has(path)) return;
  clearTimeout(pending.get(path));
  pending.set(path, setTimeout(async () => {
    pending.delete(path);
    recentlyHandled.add(path);
    setTimeout(() => recentlyHandled.delete(path), 5000);
    await handle(path);
  }, 600));
}

console.log(`watching   ${WATCH_DIR}`);
console.log(`quarantine ${QUARANTINE}${DRY_RUN ? "  (dry run, nothing will be moved)" : ""}`);
console.log(`threshold  ${MIN} and above\n`);

watch(WATCH_DIR, { recursive: true }, (_event, filename) => {
  if (!filename) return;
  schedule(join(WATCH_DIR, filename.toString()));
});

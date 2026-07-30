/**
 * Minimal zip reader.
 *
 * Office files are zip containers. Shelling out to `unzip` worked on macOS and
 * silently made the tool undeployable on Windows, where there is no such binary.
 * This reads the container directly, so the scanner runs anywhere Bun runs with
 * no external commands and no dependencies.
 */
import { inflateRawSync } from "node:zlib";

const EOCD_SIG = 0x06054b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const ZIP64_EOCD_LOCATOR_SIG = 0x07064b50;
const ZIP64_EOCD_SIG = 0x06064b50;

export type ZipEntry = {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
};

export class NotAZipError extends Error {}

/** Locates the End of Central Directory record, which lives at the tail. */
function findEocd(buf: Buffer): number {
  const max = Math.min(buf.length, 0xffff + 22);
  for (let i = 22; i <= max; i++) {
    const pos = buf.length - i;
    if (pos < 0) break;
    if (buf.readUInt32LE(pos) === EOCD_SIG) return pos;
  }
  throw new NotAZipError("no end-of-central-directory record");
}

export function listEntries(buf: Buffer): ZipEntry[] {
  if (buf.length < 22) throw new NotAZipError("file too small to be a zip");

  const eocd = findEocd(buf);
  let count = buf.readUInt16LE(eocd + 10);
  let dirOffset = buf.readUInt32LE(eocd + 16);

  // Zip64: the 32-bit fields are saturated and the real values live elsewhere.
  if (count === 0xffff || dirOffset === 0xffffffff) {
    const locator = eocd - 20;
    if (locator >= 0 && buf.readUInt32LE(locator) === ZIP64_EOCD_LOCATOR_SIG) {
      const z64 = Number(buf.readBigUInt64LE(locator + 8));
      if (buf.readUInt32LE(z64) === ZIP64_EOCD_SIG) {
        count = Number(buf.readBigUInt64LE(z64 + 32));
        dirOffset = Number(buf.readBigUInt64LE(z64 + 48));
      }
    }
  }

  const entries: ZipEntry[] = [];
  let pos = dirOffset;

  for (let i = 0; i < count; i++) {
    if (pos + 46 > buf.length || buf.readUInt32LE(pos) !== CENTRAL_SIG) break;

    const method = buf.readUInt16LE(pos + 10);
    const compressedSize = buf.readUInt32LE(pos + 20);
    const uncompressedSize = buf.readUInt32LE(pos + 24);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const localHeaderOffset = buf.readUInt32LE(pos + 42);
    const name = buf.toString("utf8", pos + 46, pos + 46 + nameLen);

    entries.push({ name, method, compressedSize, uncompressedSize, localHeaderOffset });
    pos += 46 + nameLen + extraLen + commentLen;
  }

  if (entries.length === 0) throw new NotAZipError("central directory empty or unreadable");
  return entries;
}

/** Returns the decompressed bytes of one entry, or null if it cannot be read. */
export function readEntry(buf: Buffer, entry: ZipEntry): Buffer | null {
  const h = entry.localHeaderOffset;
  if (h + 30 > buf.length || buf.readUInt32LE(h) !== LOCAL_SIG) return null;

  // Name and extra lengths in the LOCAL header can differ from the central one.
  const nameLen = buf.readUInt16LE(h + 26);
  const extraLen = buf.readUInt16LE(h + 28);
  const start = h + 30 + nameLen + extraLen;

  // A streamed entry writes sizes to a trailing descriptor, leaving the header
  // zeroed, so fall back to the central directory's figure.
  let size = buf.readUInt32LE(h + 18) || entry.compressedSize;
  if (!size) size = buf.length - start;

  const data = buf.subarray(start, start + size);

  try {
    if (entry.method === 0) return Buffer.from(data);
    if (entry.method === 8) return inflateRawSync(data);
    return null; // any other compression method is not used by Office
  } catch {
    return null;
  }
}

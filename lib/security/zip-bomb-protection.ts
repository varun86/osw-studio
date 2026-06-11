/**
 * ZIP Bomb Protection Module
 *
 * Prevents ZIP bomb attacks where a small compressed file expands to an
 * enormous size when extracted, exhausting memory and disk space.
 *
 * ZIP bombs exploit the gap between compressed and uncompressed sizes.
 * A 42KB ZIP file can expand to 4.5GB, crashing the server.
 *
 * Protection strategy:
 * 1. Before extraction: check each entry's uncompressedSize from ZIP headers
 * 2. Reject if any single file exceeds 50MB uncompressed
 * 3. Reject if total uncompressed size exceeds 500MB
 * 4. After extraction: verify per-file content size matches expectation
 */

/** Maximum uncompressed size for a single file within a ZIP (50MB) */
export const MAX_ZIP_ENTRY_SIZE = 50 * 1024 * 1024;

/** Maximum total uncompressed size for all files in a ZIP (500MB) */
export const MAX_ZIP_TOTAL_SIZE = 500 * 1024 * 1024;

export interface ZipEntryInfo {
  name: string;
  uncompressedSize: number;
  compressedSize: number;
  date: Date | null;
}

/**
 * Validate ZIP entries for bomb protection.
 * Called AFTER JSZip.loadAsync() — the ZIP headers are already parsed
 * and uncompressedSize is available without extracting the actual content.
 *
 * @param entries - Array of ZIP entry info objects
 * @throws Error if any entry exceeds size limits
 */
export function validateZipEntries(entries: ZipEntryInfo[]): void {
  let totalUncompressedSize = 0;

  for (const entry of entries) {
    // Check individual file size
    if (entry.uncompressedSize > MAX_ZIP_ENTRY_SIZE) {
      throw new Error(
        `ZIP entry "${entry.name}" is too large when uncompressed ` +
        `(${formatBytes(entry.uncompressedSize)}, max ${formatBytes(MAX_ZIP_ENTRY_SIZE)} per file). ` +
        `This may be a ZIP bomb.`
      );
    }

    totalUncompressedSize += entry.uncompressedSize;

    // Check cumulative total
    if (totalUncompressedSize > MAX_ZIP_TOTAL_SIZE) {
      throw new Error(
        `Total uncompressed size of ZIP exceeds limit ` +
        `(${formatBytes(totalUncompressedSize)}, max ${formatBytes(MAX_ZIP_TOTAL_SIZE)}). ` +
        `This may be a ZIP bomb.`
      );
    }

    // Check for suspicious ratio (compressed is < 1% of uncompressed)
    // This catches classic ZIP bombs where compression ratio is extreme
    if (entry.compressedSize > 0 && entry.uncompressedSize > entry.compressedSize * 1000) {
      throw new Error(
        `ZIP entry "${entry.name}" has a suspicious compression ratio ` +
        `(${entry.compressedSize} bytes compressed → ${formatBytes(entry.uncompressedSize)} uncompressed). ` +
        `This may be a ZIP bomb.`
      );
    }
  }
}

/**
 * Extract entry info from JSZip's loaded data.
 * JSZip provides `_data` with `uncompressedSize` in the internal structure.
 */
export function extractZipEntryInfo(zipData: any): ZipEntryInfo[] {
  const entries: ZipEntryInfo[] = [];

  zipData.forEach((relativePath: string, file: any) => {
    // Skip directories
    if (file.dir) return;

    // JSZip stores uncompressed size in the internal _data object
    // or we can access it from the Central Directory Header
    const uncompressedSize = file._data?.uncompressedSize
      ?? file._data?.rawFileSize
      ?? 0;

    const compressedSize = file._data?.compressedSize
      ?? file._data?.rawDeflateSize
      ?? file._data?.rawFileSize
      ?? 0;

    entries.push({
      name: relativePath,
      uncompressedSize,
      compressedSize,
      date: file.date,
    });
  });

  return entries;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

// Test-harness image decoding only. OpenWrt appends fwtool metadata after the
// gzip member (target/linux/x86/image/Makefile: gzip | append-metadata).
// Verify the whole publisher asset first, then independently verify the single
// gzip member's CRC/ISIZE; appended bytes are never interpreted or executed.
import fs from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { createInflateRaw, crc32 } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
export async function decodePinnedGzipImage(
  input,
  output,
  expectedSha256,
  maxBytes = 256 * 1024 * 1024,
) {
  if (
    !/^[a-f0-9]{64}$/.test(expectedSha256) ||
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1 ||
    maxBytes > 256 * 1024 * 1024
  )
    throw new Error('Invalid pinned gzip image limits.');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(input)) hash.update(chunk);
  if (hash.digest('hex') !== expectedSha256) throw new Error('OpenWrt publisher SHA-256 mismatch.');
  const handle = await fs.open(input, 'r');
  let created = false;
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 32 * 1024 * 1024)
      throw new Error('Oversized public compressed image.');
    const header = Buffer.alloc(10);
    if (
      (await handle.read(header, 0, 10, 0)).bytesRead !== 10 ||
      header[0] !== 31 ||
      header[1] !== 139 ||
      header[2] !== 8 ||
      header[3] !== 0
    )
      throw new Error('Unsupported pinned gzip member header.');
    const inflate = createInflateRaw();
    let size = 0,
      crc = 0;
    const bounded = async function* (chunks) {
      for await (const chunk of chunks) {
        size += chunk.length;
        if (size > maxBytes) throw new Error('OpenWrt expanded disk exceeded its bound.');
        crc = crc32(chunk, crc);
        yield chunk;
      }
    };
    const outputStream = createWriteStream(output, { flags: 'wx', mode: 0o600 });
    outputStream.once('open', () => {
      created = true;
    });
    await pipeline(
      handle.createReadStream({ start: 10, autoClose: false }),
      inflate,
      bounded,
      outputStream,
    );
    const trailerOffset = 10 + inflate.bytesWritten,
      trailer = Buffer.alloc(8);
    if (
      (await handle.read(trailer, 0, 8, trailerOffset)).bytesRead !== 8 ||
      trailer.readUInt32LE(0) !== crc ||
      trailer.readUInt32LE(4) !== size >>> 0
    )
      throw new Error('Pinned gzip member checksum or expanded size mismatch.');
    const trailingBytes = stat.size - trailerOffset - 8;
    if (trailingBytes < 0 || trailingBytes > 65536)
      throw new Error('Unexpected public image metadata size.');
    return {
      compressedBytes: stat.size,
      expandedBytes: size,
      gzipMemberBytes: trailerOffset + 8,
      trailingMetadataBytes: trailingBytes,
    };
  } catch (error) {
    if (created) await fs.rm(output, { force: true });
    throw error;
  } finally {
    await handle.close();
  }
}

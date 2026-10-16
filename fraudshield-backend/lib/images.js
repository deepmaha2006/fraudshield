// lib/images.js — verify uploaded images by content, not by client-supplied
// Content-Type, and read dimensions from the header so oversized
// ("decompression bomb") images are rejected before any decoder runs.

const fs = require('fs');

const MAX_PIXELS = 40 * 1000 * 1000; // ~40 MP, far beyond any phone screenshot

function sniff(buf) {
    if (buf.length >= 24 && buf.readUInt32BE(0) === 0x89504e47 && buf.readUInt32BE(4) === 0x0d0a1a0a) {
        return { type: 'png', ext: '.png', width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
    }
    if (buf.length >= 10 && buf.toString('ascii', 0, 6).match(/^GIF8[79]a$/)) {
        return { type: 'gif', ext: '.gif', width: buf.readUInt16LE(6), height: buf.readUInt16LE(8) };
    }
    if (buf.length >= 26 && buf.toString('ascii', 0, 2) === 'BM') {
        return { type: 'bmp', ext: '.bmp', width: Math.abs(buf.readInt32LE(18)), height: Math.abs(buf.readInt32LE(22)) };
    }
    if (buf.length >= 30 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') {
        const chunk = buf.toString('ascii', 12, 16);
        if (chunk === 'VP8X') return { type: 'webp', ext: '.webp', width: 1 + buf.readUIntLE(24, 3), height: 1 + buf.readUIntLE(27, 3) };
        if (chunk === 'VP8 ') return { type: 'webp', ext: '.webp', width: buf.readUInt16LE(26) & 0x3fff, height: buf.readUInt16LE(28) & 0x3fff };
        if (chunk === 'VP8L') {
            const b = buf.readUInt32LE(21);
            return { type: 'webp', ext: '.webp', width: 1 + (b & 0x3fff), height: 1 + ((b >> 14) & 0x3fff) };
        }
        return null;
    }
    if (buf.length >= 4 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
        // Walk JPEG segments to the first SOFn marker.
        let i = 2;
        while (i + 9 < buf.length) {
            if (buf[i] !== 0xff) { i++; continue; }
            const marker = buf[i + 1];
            if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { i += 2; continue; }
            const len = buf.readUInt16BE(i + 2);
            if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) {
                return { type: 'jpeg', ext: '.jpg', height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
            }
            i += 2 + len;
        }
        return { type: 'jpeg', ext: '.jpg', width: null, height: null };
    }
    return null;
}

/**
 * Inspect a file on disk. Returns { type, ext, width, height } or throws an
 * error with status 415/413 suitable for the client.
 * @param {string[]} allowed image types, e.g. ['png','jpeg']
 */
async function inspectImage(filePath, allowed) {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is server-generated (config dir + multer/regex-validated name), never user input
    const fh = await fs.promises.open(filePath, 'r');
    try {
        const buf = Buffer.alloc(256 * 1024);
        const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
        const info = sniff(buf.subarray(0, bytesRead));
        if (!info || !allowed.includes(info.type)) {
            throw Object.assign(new Error(`File content is not an accepted image (${allowed.join(', ')}).`), { status: 415, expose: true });
        }
        if (!info.width || !info.height) {
            throw Object.assign(new Error('Could not read image dimensions.'), { status: 415, expose: true });
        }
        if (info.width * info.height > MAX_PIXELS) {
            throw Object.assign(new Error('Image resolution is too large.'), { status: 413, expose: true });
        }
        return info;
    } finally {
        await fh.close();
    }
}

module.exports = { inspectImage, sniff, MAX_PIXELS };

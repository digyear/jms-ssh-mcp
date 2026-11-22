import { createHmac } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(secret) {
    const cleaned = String(secret).replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
    let bits = '';
    for (const char of cleaned) {
        const index = ALPHABET.indexOf(char);
        if (index < 0) throw new Error(`invalid base32 character "${char}"`);
        bits += index.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return Buffer.from(bytes);
}

// RFC 6238 with the parameters every authenticator app defaults to.
export function totp(secret, { now = Date.now(), step = 30, digits = 6 } = {}) {
    const counter = Math.floor(now / 1000 / step);
    const message = Buffer.alloc(8);
    message.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
    message.writeUInt32BE(counter >>> 0, 4);
    const digest = createHmac('sha1', base32Decode(secret)).update(message).digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const binary = digest.readUInt32BE(offset) & 0x7fffffff;
    return String(binary % 10 ** digits).padStart(digits, '0');
}

export function secondsRemaining({ now = Date.now(), step = 30 } = {}) {
    return step - (Math.floor(now / 1000) % step);
}

export function parseOtpAuthUri(uri) {
    const url = new URL(uri);
    if (url.protocol !== 'otpauth:') throw new Error('not an otpauth:// URI');
    const secret = url.searchParams.get('secret');
    if (!secret) throw new Error('otpauth URI has no secret');
    return {
        type: url.host,
        secret,
        label: decodeURIComponent(url.pathname.replace(/^\//, '')),
        issuer: url.searchParams.get('issuer') || null,
        digits: Number(url.searchParams.get('digits') || 6),
        period: Number(url.searchParams.get('period') || 30),
    };
}
const ANSI = /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[()][A-B0-9]|\r/g;

export function stripAnsi(text) {
    return String(text).replace(ANSI, '');
}

// Binary data reaching an error message turns it into noise: NULs and control
// characters are replaced, and long runs collapse, so the tail stays readable.
export function tail(text, maxChars = 400) {
    const flat = stripAnsi(text)
        .replace(/[\u0000-\u0008\u000e-\u001f\u007f]/g, '')
        .replace(/\s+/g, ' ')
        .trim();
    return flat.length > maxChars ? `…${flat.slice(-maxChars)}` : flat;
}

// Keep both ends: logs lose the interesting part when you only cut the tail,
// and a 200 MB journal read must never enter the model context whole.
export function truncateOutput(text, maxBytes) {
    const buffer = Buffer.from(text, 'utf8');
    if (buffer.length <= maxBytes) return { text, truncated: false, bytes: buffer.length };
    const headBytes = Math.floor(maxBytes * 0.2);
    const tailBytes = maxBytes - headBytes;
    return {
        text: `${buffer.subarray(0, headBytes).toString('utf8')}\n…[truncated ${buffer.length - maxBytes} bytes]…\n${buffer.subarray(buffer.length - tailBytes).toString('utf8')}`,
        truncated: true,
        bytes: buffer.length,
    };
}

export function redact(text, secrets = []) {
    let out = String(text);
    for (const secret of secrets) {
        if (secret && secret.length >= 4) out = out.split(secret).join('***');
    }
    return out;
}

export function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function decodeEnterKey(value) {
    if (value === undefined || value === null || value === '') return '\r';
    if (/^cr$/i.test(value)) return '\r';
    if (/^lf$/i.test(value)) return '\n';
    if (value === '\\r') return '\r';
    if (value === '\\n') return '\n';
    const code = Number(value);
    return Number.isInteger(code) ? String.fromCharCode(code) : value;
}
// A NUL byte costs six bytes once JSON-escaped (\u0000), so a binary file read
// as text can inflate a reply by an order of magnitude. Strip the control
// characters that no log needs and report how much was dropped.
export function sanitizeForJson(text) {
    if (!text) return { text: '', removed: 0 };
    const cleaned = text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
    return { text: cleaned, removed: text.length - cleaned.length };
}

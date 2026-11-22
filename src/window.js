// A shell can produce gigabytes (journalctl on a busy host, a log file opened by
// mistake). Whatever the caller asks for, this process must not grow with the
// output: the window keeps a bounded head and a bounded tail, and remembers how
// much it threw away.
export class OutputWindow {
    constructor({ maxChars = 1 << 20, headChars = null, tailChars = null } = {}) {
        this.maxChars = maxChars;
        this.headChars = headChars ?? Math.floor(maxChars * 0.2);
        this.tailChars = tailChars ?? maxChars - this.headChars;
        this.reset();
    }

    reset() {
        this.head = '';
        this.chunks = [];
        this.tailLength = 0;
        this.droppedChars = 0;
        this.totalChars = 0;
        this.deltaSinceRead = '';
    }

    append(chunk) {
        const text = String(chunk);
        if (!text) return;
        this.totalChars += text.length;

        if (this.head.length < this.headChars) {
            const take = Math.min(this.headChars - this.head.length, text.length);
            this.head += text.slice(0, take);
            chunk = text.slice(take);
            if (!chunk) return;
        }

        this.chunks.push(chunk);
        this.tailLength += chunk.length;
        while (this.tailLength > this.tailChars && this.chunks.length > 1) {
            const removed = this.chunks.shift();
            this.tailLength -= removed.length;
            this.droppedChars += removed.length;
        }
        if (this.tailLength > this.tailChars) {
            const overflow = this.tailLength - this.tailChars;
            this.chunks[0] = this.chunks[0].slice(overflow);
            this.tailLength -= overflow;
            this.droppedChars += overflow;
        }

        // Live readers (progress notifications) get a bounded slice, never the
        // whole chunk: the network must not become the new memory sink.
        this.deltaSinceRead = (this.deltaSinceRead + text).slice(-4096);
    }

    takeDelta() {
        const delta = this.deltaSinceRead;
        this.deltaSinceRead = '';
        return delta;
    }

    tail(count = 1000) {
        let remaining = Math.max(0, count);
        if (remaining === 0) return '';
        const parts = [];
        for (let i = this.chunks.length - 1; i >= 0 && remaining > 0; i -= 1) {
            const chunk = this.chunks[i];
            if (chunk.length <= remaining) {
                parts.unshift(chunk);
                remaining -= chunk.length;
            } else {
                parts.unshift(chunk.slice(chunk.length - remaining));
                remaining = 0;
            }
        }
        // Short output never leaves the head buffer, so it has to be part of the
        // tail too — otherwise a quiet shell reports no prompt at all.
        if (remaining > 0 && this.head) parts.unshift(this.head.slice(-remaining));
        return parts.join('');
    }

    text() {
        const body = this.chunks.join('');
        if (!this.droppedChars) return `${this.head}${body}`;
        return `${this.head}\n…[${this.droppedChars} chars dropped]…\n${body}`;
    }

    get length() {
        return this.head.length + this.tailLength;
    }
}
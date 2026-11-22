import { Client } from 'ssh2';
import { StringDecoder } from 'node:string_decoder';
import { randomBytes } from 'node:crypto';
import { totp } from './totp.js';
import { parseAssetList, parsePageInfo } from './menu.js';
import { sleep, stripAnsi, tail, truncateOutput } from './util.js';
import { OutputWindow } from './window.js';

// A bastion prints these words in its own UI language; the non-ASCII ones are
// escaped so the source stays ASCII.
const OTP_PROMPT = /otp|one[- ]?time|verification code|auth(?:entication)? code|token|\u52A8\u6001|\u9A8C\u8BC1\u7801|\u4EE4\u724C/i;
const PASSWORD_PROMPT = /password|\u5BC6\u7801/i;
const PAGER_PROMPT = /--\s*more\s*--|\(END\)|:\s*$/i;

export class BastionSession {
    constructor({ id, owner = 'default', profile, defaults, logger = () => {} }) {
        this.ownerKey = owner;
        // One shell means one stdin: concurrent callers must take turns, or two
        // commands interleave and the marker of one lands in the buffer of the
        // other.
        this.queue = Promise.resolve();
        this.id = id;
        this.owner = owner;
        this.profile = profile;
        this.defaults = defaults;
        this.logger = logger;
        this.conn = null;
        this.shell = null;
        this.window = new OutputWindow({ maxChars: defaults.maxBufferChars || (4 << 20) });
        this.decoder = new StringDecoder('utf8');
        this.connected = false;
        this.landed = false;
        this.asset = null;
        this.assetAliases = [];
        this.dropReason = null;
        this.createdAt = new Date();
        this.lastActivity = Date.now();
        this.pendingWrites = [];

        this.menuRegex = new RegExp(profile.menuPrompt);
        this.shellRegex = new RegExp(profile.shellPrompt);
        this.listRegex = new RegExp(profile.listPrompt);
    }

    #serialize(task) {
        const run = this.queue.then(task, task);
        this.queue = run.then(() => {}, () => {});
        return run;
    }

    get info() {
        return {
            sessionId: this.id,
            owner: this.owner,
            bastion: `${this.profile.username}@${this.profile.host}:${this.profile.port}`,
            asset: this.asset,
            connected: this.connected,
            atTargetShell: this.landed,
            idleMs: Date.now() - this.lastActivity,
            bufferChars: this.window.length,
            droppedChars: this.window.droppedChars,
            uptimeMs: Date.now() - this.createdAt.getTime(),
            ...(this.dropReason ? { dropReason: this.dropReason } : {}),
        };
    }

    // ------------------------------------------------------------------ connect

    async connect({ asset = null, account = null } = {}) {
        const { host, port, password, privateKey, passphrase, enterKey } = this.profile;
        // JumpServer accepts "<login>@<system user>@<asset>" as the SSH username,
        // which lands on the target shell without the menu. Everything the menu
        // path has to work around — waiting for text, CR submits, option digits,
        // row numbers — disappears when this is available.
        const username = account && asset ? `${this.profile.username}@${account}@${asset}` : this.profile.username;
        this.direct = Boolean(account && asset);
        const conn = new Client();
        this.conn = conn;
        this.dropReason = null;
        this.window.reset();

        conn.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
            const answers = prompts.map(prompt => this.#answerPrompt(prompt.prompt));
            this.logger(`keyboard-interactive: ${prompts.map(p => p.prompt).join(' | ')}`);
            finish(answers);
        });
        // A reconnect replaces this.conn; late events from the old socket must
        // not mark the fresh session as dropped.
        conn.on('error', err => { if (this.conn === conn) this.#markDropped(err.message); });
        conn.on('close', () => { if (this.conn === conn) this.#markDropped('connection closed by remote host'); });

        await new Promise((resolve, reject) => {
            const onReady = () => { conn.removeListener('error', onError); resolve(); };
            const onError = err => { conn.removeListener('ready', onReady); reject(err); };
            conn.once('ready', onReady);
            conn.once('error', onError);
            conn.connect({
                host,
                port,
                username,
                ...(privateKey ? { privateKey, passphrase } : { password }),
                tryKeyboard: true,
                keepaliveInterval: this.defaults.keepaliveIntervalMs,
                keepaliveCountMax: 3,
                readyTimeout: this.defaults.connectTimeoutMs,
            });
        });

        let stream = null;
        this.shell = await new Promise((resolve, reject) => {
            conn.shell({ term: 'xterm-256color', rows: 50, cols: 200 }, (err, opened) => {
                if (err) return reject(err);
                stream = opened;
                resolve(opened);
            });
        });
        this.connected = true;
        this.shell.on('data', chunk => {
            this.window.append(this.decoder.write(chunk));
            this.lastActivity = Date.now();
        });
        this.shell.on('close', () => { if (this.shell === stream) this.#markDropped('shell closed by remote host'); });
        this.shell.on('error', err => { if (this.shell === stream) this.#markDropped(err.message); });

        if (this.direct) {
            await this.#waitFor(this.shellRegex, {
                timeoutMs: this.defaults.connectTimeoutMs,
                label: `target shell for ${asset} (direct asset login as ${username})`,
            });
            this.asset = asset;
            this.assetAliases = [asset];
            this.landed = true;
            await this.#prepareShell();
            return this.info;
        }

        const first = await this.#waitForAny(
            [{ regex: this.menuRegex, label: 'bastion menu' }, { regex: this.shellRegex, label: 'shell prompt' }],
            { timeoutMs: this.defaults.connectTimeoutMs, label: 'bastion greeting' },
        );

        if (first === 'shell prompt' && !asset) {
            this.landed = true;
            return this.info;
        }
        if (asset) {
            await this.#selectAsset(asset, account);
        }
        await this.#prepareShell();
        return this.info;
    }

    // A pager that survives the menu (journalctl, man, git) would swallow the
    // marker line and every exec would time out, so pin the pager off.
    async #prepareShell() {
        if (!this.landed) return;
        const quiet = 'export PAGER=cat SYSTEMD_PAGER=cat GIT_PAGER=cat MANPAGER=cat LESS=FRX';
        try {
            await this.exec(quiet, { timeoutMs: 5000, skipAllowlist: true, silent: true });
        } catch (err) {
            this.logger(`pager prelude failed: ${err.message}`);
        }
    }

    #answerPrompt(text) {
        const secret = this.profile.otpSecret;
        if (OTP_PROMPT.test(text)) {
            if (!secret) throw new Error(`Bastion asked for an OTP ("${text}") but no otpSecret is configured`);
            return totp(secret);
        }
        if (PASSWORD_PROMPT.test(text)) return this.profile.password || '';
        return '';
    }

    // --------------------------------------------------------- asset selection

    async selectAsset(asset, account = null) {
        return this.#serialize(() => this.#selectAsset(asset, account));
    }

    async #selectAsset(asset, account = null) {
        const value = String(asset).trim();
        // Menu options 1..11 are commands (2 = search, 9 = language ...), so a
        // numeric id inside that range is swallowed by the menu; the caller has
        // to name the asset by IP or hostname instead.
        if (/^\d{1,2}$/.test(value) && Number(value) <= this.defaults.menuOptionMax) {
            throw new Error(`Asset "${value}" falls inside the bastion menu's own option range (1-${this.defaults.menuOptionMax}), `
                + 'so the menu reads it as a command. Select by IP or hostname instead — jms_ssh_hosts returns both.');
        }

        this.landed = false;
        const startedAt = Date.now();
        while (!this.#atMenuPrompt()) {
            if (Date.now() - startedAt > this.defaults.connectTimeoutMs) {
                throw new Error(`No bastion prompt to answer (expected ${this.profile.menuPrompt} or ${this.profile.listPrompt}). `
                    + `Host said: "${tail(this.window.tail(600), 200)}"`);
            }
            await sleep(80);
        }

        // At the menu a term may be taken as a fuzzy search rather than a login.
        // The result list that follows is answered with row numbers (1..N), not
        // with asset ids, so the requested term has to be mapped to its row.
        let hit = await this.#typeAndWait(value);
        if (hit === 'bastion list prompt') {
            const rows = parseAssetList(stripAnsi(this.window.text()));
            const choice = this.#chooseRow(rows, value);
            if (choice !== null) {
                this.logger(`"${value}" searched to ${rows.length} row(s); selecting row ${choice.index}`);
                this.#rememberAliases(choice.row);
                hit = await this.#typeAndWait(String(choice.index));
            }
        }

        if (hit === 'shell prompt') {
            this.landed = true;
            this.asset = value;
            this.assetAliases = [...new Set([value, ...this.assetAliases])];
            this.logger(`landed on asset ${value}`);
            return this.info;
        }

        if (account) {
            const afterAccount = await this.#typeAndWait(account);
            if (afterAccount === 'shell prompt') {
                this.landed = true;
                this.asset = value;
                return this.info;
            }
        }

        throw new Error(`Bastion did not open a shell for "${value}" — it wants another choice (account?) or nothing matched. `
            + `Pass account explicitly, or use the exact IP/hostname from jms_ssh_hosts. Bastion said: "${tail(this.window.tail(900), 300)}"`);
    }

    // Every spelling the caller used for this asset should hit the same
    // connection: id, IP, hostname.
    #rememberAliases(row) {
        if (!row) return;
        for (const alias of [row.id, row.ip, row.name]) {
            if (alias) this.assetAliases = [...new Set([...this.assetAliases, String(alias)])];
        }
    }

    #chooseRow(rows, term) {
        // Search results number their rows 1..N; that first column is a row
        // index, not an asset id, so matching on it would be wrong.
        const needle = String(term).toLowerCase();
        const exact = rows.filter(row =>
            String(row.ip || '').toLowerCase() === needle
            || String(row.name || '').toLowerCase() === needle);
        const asChoice = row => ({ index: rows.indexOf(row) + 1, row });
        if (exact.length === 1) return asChoice(exact[0]);
        if (rows.length === 1) return asChoice(rows[0]);
        const fuzzy = rows.filter(row => JSON.stringify([row.name, row.ip, row.note]).toLowerCase().includes(needle));
        if (fuzzy.length === 1) return asChoice(fuzzy[0]);
        if (rows.length > 0) {
            const preview = rows.slice(0, 15)
                .map((row, index) => `${index + 1}) id=${row.id} ${row.name || ''} ${row.ip || ''}`.trim())
                .join('; ');
            throw new Error(`"${term}" matched ${rows.length} assets — pass an exact IP or hostname. Candidates: ${preview}`);
        }
        return null;
    }

    async #typeAndWait(value) {
        this.window.reset();
        this.shell.write(`${value}${this.profile.enterKey}`);
        return this.#waitForAny(
            [
                { regex: this.shellRegex, label: 'shell prompt' },
                { regex: this.menuRegex, label: 'bastion menu' },
                { regex: this.listRegex, label: 'bastion list prompt' },
            ],
            { timeoutMs: this.defaults.connectTimeoutMs, label: `asset "${value}"` },
        );
    }

    // ------------------------------------------------------------------- exec

    async exec(command, options = {}) {
        return this.#serialize(() => this.#exec(command, options));
    }

    async #exec(command, { timeoutMs, maxBytes, skipAllowlist = false, silent = false } = {}) {
        this.#assertConnected();
        this.#syncLandingState();
        if (!this.landed) {
            if (!this.asset) {
                throw new Error(`Session ${this.id} is on the bastion menu. Call jms_select_asset first.`);
            }
            await this.#selectAsset(this.asset);
        }
        const timeout = timeoutMs || this.defaults.commandTimeoutMs;
        const marker = `JMS${randomBytes(4).toString('hex')}`;
        const enter = this.profile.enterKey;

        this.window.reset();
        // The marker carries $? so the caller gets an exit status instead of
        // guessing from the prompt, which bastions make unparseable anyway.
        this.shell.write(`${command}${enter}printf '\\n__${marker}__%s\\n' "$?"${enter}`);
        const markerRegex = new RegExp(`__${marker}__(\\d+)`);
        try {
            await this.#waitFor(markerRegex, { timeoutMs: timeout, label: `command "${firstLine(command)}"`, pagerKey: 'q' });
        } catch (err) {
            // A command that outlives its timeout is still writing into the
            // shell; without an interrupt every later command would queue
            // behind it and read its leftovers.
            try { this.shell.write('\u0003'); } catch { /* already gone */ }
            await this.#waitForAny([{ regex: this.shellRegex, label: 'shell prompt' }], {
                timeoutMs: 5000,
                label: 'prompt after interrupt',
            }).catch(() => {});
            throw new Error(`${err.message} — interrupted with Ctrl-C; narrow the command (tail -n, head -c, grep -E) instead of reading a whole file`);
        } finally { /* the interrupt path above already restored the shell */ }

        const raw = stripAnsi(this.window.text());
        const match = raw.match(markerRegex);
        const exitCode = Number(match[1]);
        let body = raw.slice(0, match.index);

        // Drop the tty echo of what we typed, and the blank line before it.
        body = body.split(/\r?\n/)
            .filter(line => !line.includes(marker))
            .filter(line => line.trim() !== command.trim())
            .join('\n')
            .replace(/^\s*\n/, '')
            .trimEnd();

        this.lastActivity = Date.now();
        const { text, truncated } = truncateOutput(body, maxBytes || this.defaults.maxOutputBytes);
        return {
            sessionId: this.id,
            command: silent ? undefined : command,
            exitCode,
            output: text,
            truncated,
        };
    }

    async listAssets(options = {}) {
        return this.#serialize(() => this.#listAssets(options));
    }

    async #listAssets({ filter = null, limit = 200, scope = 'p', maxPages = 5 } = {}) {
        this.#assertConnected();
        if (this.landed) {
            throw new Error(`Session ${this.id} is on the target shell, where "${scope}" is a shell command. `
                + 'Ask the bastion menu instead — call jms_ssh_hosts with a host that is not on the target shell.');
        }

        const enter = this.profile.enterKey;
        const timeout = this.defaults.commandTimeoutMs;
        this.window.reset();
        this.shell.write(`${scope}${enter}`);
        let page = await this.#waitForAny(
            [{ regex: this.listRegex, label: 'list prompt' }, { regex: this.menuRegex, label: 'menu' }],
            { timeoutMs: timeout, label: 'asset list' },
        );

        let raw = stripAnsi(this.window.text());
        let pageInfo = parsePageInfo(raw);
        let pagesRead = 1;

        // JumpServer pages the table at ~40 rows and only repeats the footer on
        // each page, so the page count has to be read again per chunk.
        while (page === 'list prompt' && pagesRead < Math.min(maxPages, Math.max(pageInfo.pages, 1))) {
            this.window.reset();
            this.shell.write(`n${enter}`);
            await this.#waitForAny([{ regex: this.listRegex, label: 'list prompt' }], { timeoutMs: timeout, label: 'next page' });
            const chunk = stripAnsi(this.window.tail(200000));
            const chunkInfo = parsePageInfo(chunk);
            if (chunkInfo.pages > 1) pageInfo = chunkInfo;
            raw += `\n${chunk}`;
            pagesRead += 1;
        }

        if (page === 'list prompt') {
            try {
                this.window.reset();
                this.shell.write(`q${enter}`);
                await this.#waitFor(this.menuRegex, { timeoutMs: timeout, label: 'menu after asset list', pagerKey: null });
            } catch (err) {
                this.logger(`could not leave the asset list: ${err.message}`);
            }
        }

        this.lastActivity = Date.now();
        let assets = parseAssetList(raw);
        if (filter) {
            const regex = new RegExp(filter, 'i');
            assets = assets.filter(item => regex.test(JSON.stringify(item)));
        }
        return {
            sessionId: this.id,
            scope,
            pages: pagesRead,
            total: pageInfo.total ?? assets.length,
            count: assets.length,
            assets: assets.slice(0, limit),
        };
    }

    // ------------------------------------------------------------- teardown

    async disconnect() {
        this.connected = false;
        try {
            if (this.shell && this.landed) this.shell.write(`exit${this.profile.enterKey}`);
            await sleep(200);
            this.conn?.end();
        } catch {
            // closing a half-dead session must never throw
        }
        this.shell = null;
        this.conn = null;
    }

    #markDropped(reason) {
        if (!this.connected && this.dropReason) return;
        this.connected = false;
        this.landed = false;
        this.dropReason = reason;
        this.logger(`session dropped: ${reason}`);
    }

    // Prompt matching has to run on ANSI-free text: KoKo redraws the prompt with
    // cursor escapes, so a raw buffer ends in \x1b[5D\x1b[K rather than "Opt> ".
    #tailText(chars = 1000) {
        return stripAnsi(this.window.tail(chars * 2)).slice(-chars);
    }

    // Reading slower only helps when the throttle reaches the sender: pausing the
    // channel closes the SSH window, so the remote blocks in write() instead of
    // this side dropping what it cannot keep.
    #atMenuPrompt() {
        const window = this.#tailText(400);
        return this.menuRegex.test(window) || this.listRegex.test(window);
    }

    // `exit` on the target does not drop the SSH connection: KoKo logs out and
    // shows its own prompt again. Landing state has to be re-derived from what
    // the shell is showing, not from the socket being alive.
    #syncLandingState() {
        if (this.landed && this.#atMenuPrompt()) {
            this.logger('left the target shell (bastion prompt is back)');
            this.landed = false;
        }
        return this.landed;
    }

    #assertConnected() {
        if (!this.connected || !this.shell) {
            throw new Error(`Session ${this.id} is not connected${this.dropReason ? ` (${this.dropReason})` : ''}. `
                + 'Call jms_reconnect or jms_connect again.');
        }
    }

    #assertUsable() {
        if (!this.connected || !this.shell) {
            throw new Error(`Session ${this.id} is not connected${this.dropReason ? ` (${this.dropReason})` : ''}. `
                + 'Call jms_reconnect or jms_connect again.');
        }
        if (!this.landed) {
            throw new Error(`Session ${this.id} is still on the bastion menu. Call jms_select_asset first.`);
        }
    }

    // ------------------------------------------------------------- waiting

    async #waitFor(regex, { timeoutMs, label, pagerKey = 'q' }) {
        const startedAt = Date.now();
        let pagerHits = 0;
        while (true) {
            if (regex.test(this.#tailText())) return true;
            if (this.landed && this.#atMenuPrompt()) {
                this.#syncLandingState();
                throw new Error(`${label}: the shell left the target host and is back at the bastion prompt. `
                    + `Host said: "${tail(this.window.tail(600), 200)}"`);
            }
            if (!this.connected && this.dropReason) {
                throw new Error(`${label}: session dropped (${this.dropReason}). Last output: "${tail(this.window.tail(600), 200)}"`);
            }
            if (pagerKey && PAGER_PROMPT.test(this.window.tail(200))) {
                pagerHits += 1;
                if (pagerHits < 200) {
                    try { this.shell.write(pagerKey); } catch { /* the wait reports it */ }
                }
            }
            if (Date.now() - startedAt > timeoutMs) {
                throw new Error(`${label}: timed out after ${timeoutMs}ms. Host said: "${tail(this.window.tail(900), 300)}"`);
            }
            await sleep(80);
        }
    }

    async #waitForAny(candidates, { timeoutMs, label }) {
        const startedAt = Date.now();
        while (true) {
            for (const candidate of candidates) {
                if (candidate.regex.test(this.#tailText())) return candidate.label;
            }
            if (!this.connected && this.dropReason) {
                throw new Error(`${label}: session dropped (${this.dropReason}). Last output: "${tail(this.window.tail(600), 200)}"`);
            }
            if (Date.now() - startedAt > timeoutMs) {
                throw new Error(`${label}: timed out after ${timeoutMs}ms. Host said: "${tail(this.window.tail(900), 300)}"`);
            }
            await sleep(80);
        }
    }
}

function firstLine(text) {
    const line = String(text).split(/\r?\n/)[0];
    return line.length > 60 ? `${line.slice(0, 60)}…` : line;
}
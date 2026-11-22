#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { loadConfig, resolveBastion, isCommandAllowed } from './config.js';
import { BastionSession } from './session.js';
import { appendFileSync, readFileSync } from 'node:fs';
import { redact, sanitizeForJson, truncateOutput } from './util.js';

// Read at startup so the handshake cannot disagree with package.json.
const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

// `npx jms-ssh-mcp --help` must answer instead of opening a stdio server nobody
// is talking to.
const argv = process.argv.slice(2);
if (argv.includes('--version') || argv.includes('-v')) {
    process.stdout.write(`${VERSION}\n`);
    process.exit(0);
}
if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write([
        `jms-ssh-mcp ${VERSION} - MCP server for SSH bastions behind password + TOTP`,
        '',
        'Usage: jms-ssh-mcp            serve MCP over stdio',
        '       jms-ssh-mcp --version  print the version',
        '       jms-ssh-mcp --help     print this text',
        '',
        'Required environment:',
        '  JMS_SSH_HOST             bastion hostname or address',
        '  JMS_SSH_USERNAME         bastion account',
        '  JMS_SSH_PASSWORD         password (or JMS_SSH_PASSWORD_ENV naming it)',
        '  JMS_SSH_OTP_SECRET       TOTP seed, base32 (or JMS_SSH_OTP_SECRET_ENV)',
        '',
        'Common options: JMS_SSH_PORT, JMS_SSH_ACCOUNT, JMS_SSH_HOST_WHITELIST,',
        'JMS_SSH_ALLOW_ALL, JMS_SSH_MAX_OUTPUT_BYTES, JMS_SSH_MAX_RESULT_BYTES,',
        'JMS_SSH_AUDIT_LOG. Every option and default is listed in the README.',
        '',
    ].join('\n'));
    process.exit(0);
}

const config = loadConfig();

// Host-keyed connections: the agent names a host, the server finds or opens the
// connection behind it. Session ids stay internal.
const sessions = new Map();
const byHost = new Map();
const connecting = new Map();
let sessionSeq = 0;

// One JSON line per command attempt, refused ones included. The bastion records
// the session as a video; this records what was asked, in a form jq can answer.
const AUDIT_LOG = config.defaults.auditLog;
const AUDIT_KEEP_OUTPUT = config.defaults.auditOutput;

function audit(entry) {
    if (!AUDIT_LOG) return;
    const line = JSON.stringify({
        ts: new Date().toISOString(),
        pid: process.pid,
        client: (() => {
            try { return server.server.getClientVersion()?.name || null; } catch { return null; }
        })(),
        ...entry,
    });
    try {
        appendFileSync(AUDIT_LOG, `${line}\n`, { mode: 0o600 });
    } catch (err) {
        log(`audit write failed: ${err.message}`);
    }
}

const log = message => {
    if (config.defaults.debug) process.stderr.write(`[jms-ssh-mcp] ${message}\n`);
};

const normalizeHost = host => String(host || '').trim().toLowerCase();
const newSessionId = () => `s${(sessionSeq += 1)}`;

// One reply must never be able to take the host down: the serialized JSON is the
// thing that actually crosses the transport, so the cap is on its bytes, after
// escaping, not on the character count of one field.
const MAX_RESULT_BYTES = config.defaults.maxResultBytes;

function fitToBudget(payload) {
    let text = JSON.stringify(payload, null, 2);
    if (Buffer.byteLength(text) <= MAX_RESULT_BYTES) return text;

    const trimmed = { ...payload, truncated: true };
    let body = typeof payload.output === 'string' ? payload.output : '';
    // Each pass recomputes the budget from the current cost per character instead
    // of shrinking the previous result, so one pass lands near the cap and the
    // next one only polishes it.
    for (let attempt = 0; attempt < 4 && body.length > 0; attempt += 1) {
        const shellBytes = Buffer.byteLength(JSON.stringify({ ...trimmed, output: '' }, null, 2));
        const costPerChar = Math.max(1, (Buffer.byteLength(text) - shellBytes) / body.length);
        const budget = Math.max(512, MAX_RESULT_BYTES - shellBytes);
        const targetChars = Math.floor((budget * 0.92) / costPerChar);
        if (targetChars >= body.length) return text;
        body = truncateOutput(body, Math.max(256, targetChars)).text;
        text = JSON.stringify({ ...trimmed, output: body }, null, 2);
        if (Buffer.byteLength(text) <= MAX_RESULT_BYTES) return text;
    }

    // Nothing to trim (a huge asset table, say): drop the bulk and say so.
    const { output, assets, ...rest } = trimmed;
    return JSON.stringify({
        ...rest,
        ...(assets ? { assets: assets.slice(0, 50) } : {}),
        output: '',
        note: `result exceeded JMS_SSH_MAX_RESULT_BYTES (${MAX_RESULT_BYTES} bytes); narrow the request`,
    }, null, 2);
}

const json = payload => ({ content: [{ type: 'text', text: fitToBudget(payload) }] });

const HOST_WHITELIST = config.defaults.hostWhitelist;

function hostAllowed(candidate) {
    if (HOST_WHITELIST.length === 0) return true;
    const value = String(candidate ?? '').trim().toLowerCase();
    if (!value) return false;
    return HOST_WHITELIST.some(entry => entry.toLowerCase() === value);
}

// A refusal is not a failure: the audit trail has to tell "we stopped you" from
// "it broke".
function refusal(message) {
    const err = new Error(message);
    err.refused = true;
    return err;
}

function assertHostAllowed(host) {
    // A bare asset id has to be resolved by the bastion first, so only a named
    // host can be refused before connecting.
    if (/^\d+$/.test(String(host).trim())) return;
    if (!hostAllowed(host)) {
        throw refusal(`Host "${host}" is not in JMS_SSH_HOST_WHITELIST (${HOST_WHITELIST.join(', ')})`);
    }
}

const failure = err => ({
    isError: true,
    content: [{ type: 'text', text: `Error: ${redact(err.message || String(err))}` }],
});

function dropSession(sessionId) {
    sessions.delete(sessionId);
    for (const [key, value] of byHost) {
        if (value === sessionId) byHost.delete(key);
    }
}

function evictIfNeeded() {
    const live = [...sessions.values()].sort((a, b) => a.lastActivity - b.lastActivity);
    while (live.length > config.defaults.maxSessions) {
        const victim = live.shift();
        log(`evicting least recently used connection ${victim.id} (${victim.asset})`);
        victim.disconnect();
        dropSession(victim.id);
    }
}

// One login per host even when two callers ask at the same instant: without this
// both would run the OTP round and one connection would leak.
const DEFAULT_ACCOUNT = Object.values(config.bastions).map(b => b.account).find(Boolean) || null;

async function ensureSession(host, account = null) {
    const key = `${normalizeHost(host)}|${account || ''}`;
    const existingId = byHost.get(key);
    const existing = existingId ? sessions.get(existingId) : null;
    if (existing?.info.connected) return existing;
    if (connecting.has(key)) return connecting.get(key);

    const task = (async () => {
        const profile = resolveBastion(config, null);
        const session = existing || new BastionSession({
            id: newSessionId(),
            owner: 'default',
            profile,
            defaults: config.defaults,
            logger: log,
        });
        await session.connect({ asset: session.asset || host, account });
        sessions.set(session.id, session);
        byHost.set(key, session.id);
        for (const alias of session.assetAliases) byHost.set(normalizeHost(alias), session.id);
        evictIfNeeded();
        return session;
    })().finally(() => connecting.delete(key));

    connecting.set(key, task);
    return task;
}

// A dropped socket heals once; a command that still fails afterwards is reported
// as it is.
async function runOn(host, command, options = {}, account = null) {
    const session = await ensureSession(host, account);
    // The id may resolve to something the caller never named: check what the
    // session actually landed on, not just what was asked for.
    if (!hostAllowed(session.asset || host)) {
        session.disconnect();
        dropSession(session.id);
        throw refusal(`Host "${session.asset || host}" is not in JMS_SSH_HOST_WHITELIST (${HOST_WHITELIST.join(', ')})`);
    }
    try {
        return await session.exec(command, options);
    } catch (err) {
        if (!config.defaults.reconnect || session.connected || !session.asset) throw err;
        log(`recovering ${session.id}: ${err.message}`);
        await session.connect({ asset: session.asset, account });
        return session.exec(command, options);
    }
}

// Idle reaping is opt-in: every re-login costs an OTP round.
setInterval(() => {
    if (!config.defaults.idleTimeoutMs) return;
    for (const session of [...sessions.values()]) {
        if (session.info.idleMs > config.defaults.idleTimeoutMs) {
            log(`reaping idle connection ${session.id}`);
            session.disconnect();
            dropSession(session.id);
        }
    }
}, 30000).unref();

const server = new McpServer({ name: 'jms-ssh-mcp', version: VERSION });

server.registerTool('jms_ssh_run', {
    title: 'Run a command on a host',
    description: 'Run one shell command on a host behind the bastion; returns its output and real exit code. '
        + 'The connection is opened, reused and re-entered internally — pass a host, never a session. '
        + 'Very long output is cut to head+tail (truncated: true), so narrow log reads with '
        + 'tail -n / journalctl -n / grep. Any spelling of the same asset (id, IP, hostname) reuses one connection.',
    inputSchema: {
        host: z.string().describe('Asset id, IP or hostname'),
        command: z.string().describe('Shell command, run as one line'),
        account: z.string().optional().describe('System user on the asset (e.g. root). Given, it logs in directly as '
            + '"<login>@<account>@<host>" and skips the bastion menu; omit to pick through the menu'),
        timeoutMs: z.number().int().positive().max(600000).optional().describe('Default from JMS_SSH_COMMAND_TIMEOUT_MS'),
        maxBytes: z.number().int().positive().optional().describe('Output cap for this call'),
    },
    annotations: { readOnlyHint: false, openWorldHint: true },
}, async ({ host, command, account, timeoutMs, maxBytes }) => {
    const startedAt = Date.now();
    try {
        assertHostAllowed(host);
        const guard = isCommandAllowed(command, config.defaults);
        if (!guard.allowed) {
            audit({ host, account, command, outcome: 'refused', reason: guard.reason, ms: Date.now() - startedAt });
            const blocked = refusal(guard.reason);
            blocked.audited = true;
            throw blocked;
        }
        const run = await runOn(host, command, { timeoutMs, maxBytes }, account || DEFAULT_ACCOUNT);
        const clean = sanitizeForJson(run.output);
        audit({
            host: run.asset || host,
            account,
            command,
            outcome: 'ok',
            exitCode: run.exitCode,
            ms: Date.now() - startedAt,
            outputBytes: Buffer.byteLength(clean.text),
            truncated: Boolean(run.truncated),
            ...(AUDIT_KEEP_OUTPUT ? { output: clean.text } : {}),
        });
        return json({
            host: run.asset || host,
            exitCode: run.exitCode,
            output: clean.text,
            ...(run.truncated ? { truncated: true } : {}),
            ...(clean.removed > clean.text.length * 0.01 ? { binary: true } : {}),
        });
    } catch (err) {
        if (!err.audited) {
            audit({
                host,
                account,
                command,
                outcome: err.refused ? 'refused' : 'error',
                ...(err.refused ? { reason: err.message.slice(0, 300) } : { error: redact(err.message || String(err)).slice(0, 300) }),
                ms: Date.now() - startedAt,
            });
        }
        return failure(err);
    }
});

server.registerTool('jms_ssh_hosts', {
    title: 'List hosts you may log in to',
    description: 'Ask the bastion menu for the assets this account can reach and return them parsed '
        + '(id, name, address, platform). Use the address as the host argument of jms_ssh_run.',
    inputSchema: {
        filter: z.string().optional().describe('Regex applied to each row'),
        limit: z.number().int().positive().max(2000).optional(),
        scope: z.enum(['p', 'h', 'g']).optional().describe('p assets (default), h hosts, g nodes'),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
}, async ({ filter, limit, scope }) => {
    let temp = null;
    try {
        const live = [...sessions.values()].find(session => session.connected && !session.landed);
        const session = live || (temp = new BastionSession({
            id: newSessionId(),
            owner: 'default',
            profile: resolveBastion(config, null),
            defaults: config.defaults,
            logger: log,
        }));
        if (temp) await temp.connect({});
        const listing = await session.listAssets({ filter, limit: limit ?? 200, scope: scope ?? 'p' });
        if (HOST_WHITELIST.length === 0) return json(listing);
        const assets = listing.assets.filter(asset => hostAllowed(asset.ip) || hostAllowed(asset.name));
        return json({
            ...listing,
            assets,
            count: assets.length,
            filteredByWhitelist: listing.assets.length - assets.length,
        });
    } catch (err) {
        return failure(err);
    } finally {
        if (temp) await temp.disconnect();
    }
});

server.registerTool('jms_ssh_connections', {
    title: 'Show held connections',
    description: 'Which hosts currently have a live connection behind them: shell state, idle time, and how '
        + 'much output the bounded buffer had to drop.',
    inputSchema: {},
    annotations: { readOnlyHint: true },
}, async () => json({
    count: sessions.size,
    opening: [...connecting.keys()],
    connections: [...sessions.values()].map(session => session.info),
}));

server.registerTool('jms_ssh_close', {
    title: 'Close connection(s)',
    description: 'Close the connection for one host, or all of them when no host is given.',
    inputSchema: {
        host: z.string().optional().describe('Asset id, IP or hostname; omit to close everything'),
    },
}, async ({ host }) => {
    const targets = host
        ? [...sessions.values()].filter(session => byHost.get(normalizeHost(host)) === session.id)
        : [...sessions.values()];
    if (host && targets.length === 0) return failure(new Error(`No connection for "${host}"`));
    for (const session of targets) {
        session.disconnect();
        dropSession(session.id);
    }
    return json({ closed: targets.map(session => session.asset || session.id), remaining: sessions.size });
});

const transport = new StdioServerTransport();
await server.connect(transport);
log(`ready (v${VERSION}), ${Object.keys(config.bastions).length} bastion profile(s), maxOutputBytes=${config.defaults.maxOutputBytes}`);
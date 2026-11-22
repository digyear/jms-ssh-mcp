import { readFileSync } from 'node:fs';
import { decodeEnterKey } from './util.js';

// Destructive verbs are the reason a default allowlist exists at all: a bastion
// session usually lands as root on a shared box, so "just run my command" is
// the wrong default for an agent-facing server.
const DEFAULT_ALLOWED_COMMANDS = [
    'cat', 'tac', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'fgrep', 'rg',
    'zgrep', 'zcat', 'zless', 'wc', 'sort', 'uniq', 'cut', 'tr', 'awk', 'sed',
    'ls', 'll', 'pwd', 'du', 'df', 'stat', 'file', 'tree',
    'journalctl', 'dmesg', 'uptime', 'free', 'top', 'htop', 'vmstat', 'iostat', 'mpstat',
    'lsof', 'netstat', 'ss', 'ip', 'hostname', 'uname', 'lsblk', 'blkid', 'mount',
    'find', 'ps', 'pidof', 'pgrep', 'id', 'who', 'w', 'last', 'date', 'sysctl', 'lsmod',
    'echo', 'env', 'printenv', 'which', 'type',
];

// Prefix rules, not regexes: each has to match the start of a command or of a
// pipe segment. A bare 'sudo' rule would have allowed `sudo anything`.
const DEFAULT_PREFIXES = [
    'sudo journalctl', 'sudo tail', 'sudo cat', 'sudo dmesg', 'sudo systemctl status',
    'systemctl status', 'docker logs', 'docker ps', 'docker inspect',
    'kubectl get', 'kubectl logs', 'kubectl describe', 'java -version',
];

function splitList(value) {
    return String(value || '').split(/[,\n]/).map(s => s.trim()).filter(Boolean);
}

export function loadConfig(env = process.env) {
    const fromFile = env.JMS_SSH_MCP_CONFIG ? JSON.parse(readFileSync(env.JMS_SSH_MCP_CONFIG, 'utf8')) : {};
    const fileDefaults = fromFile.defaults || {};
    const bastions = { ...(fromFile.bastions || {}) };

    // Env wins over the file, and keys the env does not mention are left alone.
    const fromEnv = Object.fromEntries(Object.entries({
        host: env.JMS_SSH_HOST,
        port: env.JMS_SSH_PORT ? Number(env.JMS_SSH_PORT) : undefined,
        username: env.JMS_SSH_USERNAME,
        password: env.JMS_SSH_PASSWORD,
        passwordEnv: env.JMS_SSH_PASSWORD_ENV,
        otpSecret: env.JMS_SSH_OTP_SECRET,
        otpSecretEnv: env.JMS_SSH_OTP_SECRET_ENV,
        menuPrompt: env.JMS_SSH_MENU_PROMPT,
        // The asset-list prompt is localized: the bracketed word changes with the UI language.
        listPrompt: env.JMS_SSH_LIST_PROMPT,
        shellPrompt: env.JMS_SSH_SHELL_PROMPT,
        account: env.JMS_SSH_ACCOUNT,
        privateKeyPath: env.JMS_SSH_PRIVATE_KEY_PATH,
        passphrase: env.JMS_SSH_PASSPHRASE,
    }).filter(([, value]) => value !== undefined));

    if (Object.keys(fromEnv).length > 0) {
        bastions.default = { ...bastions.default, ...fromEnv };
    }

    const defaults = {
        menuPrompt: env.JMS_SSH_MENU_PROMPT ?? fileDefaults.menuPrompt ?? 'Opt>\\s*$',
        listPrompt: env.JMS_SSH_LIST_PROMPT ?? fileDefaults.listPrompt
            ?? '\\[(Host|Node|Asset|Account|\u4E3B\u673A|\u8282\u70B9|\u8D44\u4EA7|\u8D26\u53F7)\\]>\\s*$',
        shellPrompt: env.JMS_SSH_SHELL_PROMPT ?? fileDefaults.shellPrompt ?? '[#$]\\s*$',
        enterKey: decodeEnterKey(env.JMS_SSH_ENTER_KEY ?? fileDefaults.enterKey ?? 'cr'),
        commandTimeoutMs: Number(env.JMS_SSH_COMMAND_TIMEOUT_MS || fileDefaults.commandTimeoutMs || 30000),
        connectTimeoutMs: Number(env.JMS_SSH_CONNECT_TIMEOUT_MS || fileDefaults.connectTimeoutMs || 20000),
        // 0 keeps sessions until they die or are closed on purpose; a bastion
        // login costs an OTP round, so dropping an idle shell is not free.
        idleTimeoutMs: Number(env.JMS_SSH_IDLE_TIMEOUT_MS ?? fileDefaults.idleTimeoutMs ?? 0),
        maxSessions: Number(env.JMS_SSH_MAX_SESSIONS || fileDefaults.maxSessions || 8),
        maxOutputBytes: Number(env.JMS_SSH_MAX_OUTPUT_BYTES || fileDefaults.maxOutputBytes || 262144),
        // Hard ceiling for a shell buffer: a runaway log can emit gigabytes and
        // the process must stay flat.
        maxBufferChars: Number(env.JMS_SSH_MAX_BUFFER_CHARS || fileDefaults.maxBufferChars || 4 << 20),
        // JumpServer's menu owns 1..11 as commands; asset ids inside that range
        // cannot be selected by number.
        menuOptionMax: Number(env.JMS_SSH_MENU_OPTION_MAX || fileDefaults.menuOptionMax || 11),
        keepaliveIntervalMs: Number(env.JMS_SSH_KEEPALIVE_MS || fileDefaults.keepaliveIntervalMs || 15000),
        reconnect: (env.JMS_SSH_RECONNECT ?? fileDefaults.reconnect ?? 'true') !== '0',
        maxResultBytes: Number(env.JMS_SSH_MAX_RESULT_BYTES || fileDefaults.maxResultBytes || 1 << 20),
        auditLog: env.JMS_SSH_AUDIT_LOG ?? fileDefaults.auditLog ?? '',
        auditOutput: (env.JMS_SSH_AUDIT_OUTPUT ?? (fileDefaults.auditOutput ? '1' : '0')) === '1',
        debug: (env.JMS_SSH_DEBUG ?? (fileDefaults.debug ? '1' : '0')) === '1',
        allowAll: env.JMS_SSH_ALLOW_ALL === '1' || fileDefaults.allowAll === true,
        // Empty means any asset the bastion offers. A non-empty list is enforced on
        // the address the session actually landed on, so an asset id cannot be used
        // to reach a host the list excludes.
        hostWhitelist: env.JMS_SSH_HOST_WHITELIST
            ? splitList(env.JMS_SSH_HOST_WHITELIST)
            : (fileDefaults.hostWhitelist || []),
        allowedCommands: env.JMS_SSH_ALLOWED_COMMANDS
            ? splitList(env.JMS_SSH_ALLOWED_COMMANDS)
            : (fileDefaults.allowedCommands || DEFAULT_ALLOWED_COMMANDS),
        allowedPrefixes: env.JMS_SSH_ALLOWED_PREFIXES
            ? splitList(env.JMS_SSH_ALLOWED_PREFIXES)
            : (fileDefaults.allowedPrefixes || DEFAULT_PREFIXES),
    };

    return { defaults, bastions };
}

export function resolveBastion(config, name, env = process.env) {
    const key = name || Object.keys(config.bastions)[0];
    if (!key) {
        throw new Error('No bastion configured. Set JMS_SSH_HOST (plus JMS_SSH_USERNAME/JMS_SSH_PASSWORD) or point JMS_SSH_MCP_CONFIG at a config file.');
    }
    const profile = config.bastions[key];
    if (!profile) {
        throw new Error(`Unknown bastion "${key}". Configured: ${Object.keys(config.bastions).join(', ') || 'none'}`);
    }
    const password = profile.password || (profile.passwordEnv ? env[profile.passwordEnv] : env.JMS_SSH_PASSWORD);
    let privateKey = profile.privateKey;
    if (!privateKey && profile.privateKeyPath) {
        try {
            privateKey = readFileSync(profile.privateKeyPath, 'utf8');
        } catch (err) {
            throw new Error(`Bastion "${key}" cannot read privateKeyPath "${profile.privateKeyPath}": ${err.message}`);
        }
    }
    const otpSecret = profile.otpSecret || (profile.otpSecretEnv ? env[profile.otpSecretEnv] : env.JMS_SSH_OTP_SECRET);
    if (!profile.host) throw new Error(`Bastion "${key}" has no host`);
    if (!profile.username) throw new Error(`Bastion "${key}" has no username`);
    if (!password && !privateKey) {
        throw new Error(`Bastion "${key}" has no password (set the env var named by passwordEnv) and no private key`);
    }
    return {
        name: key,
        host: profile.host,
        port: Number(profile.port || 2222),
        username: profile.username,
        password,
        privateKey,
        passphrase: profile.passphrase,
        otpSecret,
        account: profile.account,
        menuPrompt: profile.menuPrompt || config.defaults.menuPrompt,
        listPrompt: profile.listPrompt || config.defaults.listPrompt,
        shellPrompt: profile.shellPrompt || config.defaults.shellPrompt,
        enterKey: profile.enterKey ? decodeEnterKey(profile.enterKey) : config.defaults.enterKey,
        secrets: [password, otpSecret].filter(Boolean),
    };
}

export function isCommandAllowed(command, defaults) {
    if (defaults.allowAll) return { allowed: true };
    const trimmed = String(command).trim();
    if (!trimmed) return { allowed: false, reason: 'Empty command' };

    // A first-word check alone let "hostname; bash -i" through: the second command
    // ran as root. Refuse anything that can start one, except the two redirects
    // that read-only commands genuinely need.
    const scrutinee = trimmed.replace(/\b2>&1\b/g, '').replace(/\b2>\/dev\/null\b/g, '');
    if (/(;|&&|\|\||`|\$\(|[<>])/.test(scrutinee)) {
        return {
            allowed: false,
            reason: `Shell control operators are not allowed with the read-only allowlist: "${trimmed}". `
                + 'Run the parts as separate commands, or set JMS_SSH_ALLOW_ALL=1.',
        };
    }

    const rules = [...defaults.allowedCommands, ...defaults.allowedPrefixes];
    for (const segment of scrutinee.split('|').map(part => part.trim()).filter(Boolean)) {
        const firstWord = segment.split(/\s+/)[0].replace(/^.*\//, '');
        const matches = rules.some(rule => {
            if (rule === firstWord) return true;
            if (segment === rule || segment.startsWith(`${rule} `)) return true;
            try { return new RegExp(rule).test(segment); } catch { return false; }
        });
        if (!matches) {
            return {
                allowed: false,
                reason: `Command not in the read-only allowlist: "${segment}". `
                    + 'Add it to JMS_SSH_ALLOWED_COMMANDS, or set JMS_SSH_ALLOW_ALL=1 to disable the guard.',
            };
        }
    }
    return { allowed: true };
}

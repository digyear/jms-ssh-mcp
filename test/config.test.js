import test from 'node:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { loadConfig, resolveBastion, isCommandAllowed } from '../src/config.js';

const baseEnv = { JMS_SSH_HOST: 'jump.example.com', JMS_SSH_USERNAME: 'alice', JMS_SSH_PASSWORD: 'hunter2secret', JMS_SSH_OTP_SECRET: 'JBSWY3DPEHPK3PXP' };

test('builds a single bastion from env', () => {
    const config = loadConfig(baseEnv);
    const profile = resolveBastion(config, null, baseEnv);
    assert.equal(profile.host, 'jump.example.com');
    assert.equal(profile.port, 2222);
    assert.equal(profile.enterKey, '\r');
    assert.equal(profile.otpSecret, 'JBSWY3DPEHPK3PXP');
    assert.deepEqual(profile.secrets, ['hunter2secret', 'JBSWY3DPEHPK3PXP']);
});

test('resolves credentials through the named env vars', () => {
    const env = { ...baseEnv, MY_PASS: 'from-env-pass', MY_OTP: 'from-env-otp' };
    const config = loadConfig({
        ...env,
        JMS_SSH_PASSWORD: '',
        JMS_SSH_OTP_SECRET: '',
        JMS_SSH_PASSWORD_ENV: 'MY_PASS',
        JMS_SSH_OTP_SECRET_ENV: 'MY_OTP',
    });
    const profile = resolveBastion(config, 'default', env);
    assert.equal(profile.password, 'from-env-pass');
    assert.equal(profile.otpSecret, 'from-env-otp');
});

test('allows read-only commands and refuses destructive ones', () => {
    const { defaults } = loadConfig(baseEnv);
    assert.equal(isCommandAllowed('tail -n 100 /var/log/messages', defaults).allowed, true);
    assert.equal(isCommandAllowed('/usr/bin/journalctl -u app -n 50 --no-pager', defaults).allowed, true);
    assert.equal(isCommandAllowed('docker logs --tail 20 api', defaults).allowed, true);
    assert.equal(isCommandAllowed('rm -rf /var/lib/data', defaults).allowed, false);
    assert.equal(isCommandAllowed('dd if=/dev/zero of=/dev/sda', defaults).allowed, false);
});

test('allow-all disables the guard', () => {
    const { defaults } = loadConfig({ ...baseEnv, JMS_SSH_ALLOW_ALL: '1' });
    assert.equal(isCommandAllowed('rm -rf /tmp/x', defaults).allowed, true);
});

test('custom allowlist replaces the default set', () => {
    const { defaults } = loadConfig({ ...baseEnv, JMS_SSH_ALLOWED_COMMANDS: 'tail,cat' });
    assert.equal(isCommandAllowed('tail -n 1 /tmp/a', defaults).allowed, true);
    assert.equal(isCommandAllowed('journalctl -n 1', defaults).allowed, false);
});

test('missing bastion profile is a clear error', () => {
    const config = loadConfig(baseEnv);
    assert.throws(() => resolveBastion(config, 'nope', baseEnv), /Unknown bastion "nope"/);
});
const guardDefaults = loadConfig(baseEnv).defaults;

test('read-only allowlist refuses a second command hiding behind a first word', () => {
    for (const command of ['hostname; id', 'cat /etc/hosts && id', 'ls `id`', 'ls $(id)', 'cat /etc/hosts > /tmp/x', 'hostname | bash']) {
        const verdict = isCommandAllowed(command, guardDefaults);
        assert.equal(verdict.allowed, false, `${command} should be refused`);
    }
});

test('read-only allowlist still allows pipes between allowed commands', () => {
    for (const command of ['cat /var/log/messages | grep ERROR', 'journalctl -n 100 --no-pager | tail -5',
                           'cat /etc/hosts 2>/dev/null', 'docker ps 2>&1 | head -5']) {
        assert.equal(isCommandAllowed(command, guardDefaults).allowed, true, `${command} should be allowed`);
    }
});

test('a bare sudo rule cannot carry an arbitrary command', () => {
    assert.equal(isCommandAllowed('sudo cat /etc/hosts', guardDefaults).allowed, true);
    assert.equal(isCommandAllowed('sudo bash -i', guardDefaults).allowed, false);
});

// The deployment target has no room for a config file, so every knob has to be
// reachable from the environment alone.
const everythingFromEnv = {
    JMS_SSH_MENU_PROMPT: '^menu> $',
    JMS_SSH_LIST_PROMPT: '^list> $',
    JMS_SSH_SHELL_PROMPT: '^\\$ $',
    JMS_SSH_ENTER_KEY: 'lf',
    JMS_SSH_COMMAND_TIMEOUT_MS: '1111',
    JMS_SSH_CONNECT_TIMEOUT_MS: '2222',
    JMS_SSH_IDLE_TIMEOUT_MS: '3333',
    JMS_SSH_MAX_SESSIONS: '4',
    JMS_SSH_MAX_OUTPUT_BYTES: '5555',
    JMS_SSH_MAX_BUFFER_CHARS: '6666',
    JMS_SSH_MENU_OPTION_MAX: '7',
    JMS_SSH_KEEPALIVE_MS: '8888',
    JMS_SSH_RECONNECT: '0',
    JMS_SSH_MAX_RESULT_BYTES: '9999',
    JMS_SSH_AUDIT_LOG: '/tmp/audit.jsonl',
    JMS_SSH_AUDIT_OUTPUT: '1',
    JMS_SSH_DEBUG: '1',
    JMS_SSH_ALLOW_ALL: '1',
    JMS_SSH_ALLOWED_COMMANDS: 'cat, tail',
    JMS_SSH_ALLOWED_PREFIXES: 'docker logs, kubectl get',
};

test('every default can be set from the environment alone', () => {
    const { defaults } = loadConfig({ ...baseEnv, ...everythingFromEnv });
    assert.equal(defaults.menuPrompt, '^menu> $');
    assert.equal(defaults.listPrompt, '^list> $');
    assert.equal(defaults.shellPrompt, '^\\$ $');
    assert.equal(defaults.enterKey, '\n');
    assert.equal(defaults.commandTimeoutMs, 1111);
    assert.equal(defaults.connectTimeoutMs, 2222);
    assert.equal(defaults.idleTimeoutMs, 3333);
    assert.equal(defaults.maxSessions, 4);
    assert.equal(defaults.maxOutputBytes, 5555);
    assert.equal(defaults.maxBufferChars, 6666);
    assert.equal(defaults.menuOptionMax, 7);
    assert.equal(defaults.keepaliveIntervalMs, 8888);
    assert.equal(defaults.reconnect, false);
    assert.equal(defaults.maxResultBytes, 9999);
    assert.equal(defaults.auditLog, '/tmp/audit.jsonl');
    assert.equal(defaults.auditOutput, true);
    assert.equal(defaults.debug, true);
    assert.equal(defaults.allowAll, true);
    assert.deepEqual(defaults.allowedCommands, ['cat', 'tail']);
    assert.deepEqual(defaults.allowedPrefixes, ['docker logs', 'kubectl get']);
});

test('bastion settings come from the environment too', () => {
    const config = loadConfig({ ...baseEnv, ...everythingFromEnv, JMS_SSH_ACCOUNT: 'root',
                                JMS_SSH_PRIVATE_KEY_PATH: '/dev/null' });
    const profile = resolveBastion(config, null, { ...everythingFromEnv, JMS_SSH_ACCOUNT: 'root' });
    assert.equal(profile.account, 'root');
    assert.equal(profile.menuPrompt, '^menu> $');
    assert.equal(profile.enterKey, '\n');
});

test('env overrides the config file for the same key', () => {
    // Written outside the repo: a test must not leave a file behind for the
    // next `git status` to trip over.
    const dir = mkdtempSync(join(tmpdir(), 'jms-config-'));
    const file = join(dir, 'bastions.json');
    writeFileSync(file, JSON.stringify({
        defaults: { shellPrompt: 'from-file' },
        bastions: { default: { shellPrompt: 'from-file', username: 'file-user' } },
    }));
    const config = loadConfig({ JMS_SSH_MCP_CONFIG: file, ...baseEnv,
                                JMS_SSH_SHELL_PROMPT: 'from-env' });
    assert.equal(config.defaults.shellPrompt, 'from-env');
    assert.equal(config.bastions.default.username, 'alice');
    // Not mentioned in the environment: the file value survives.
    assert.equal(config.bastions.default.menuPrompt, undefined);
});

test('a private key can be given as a path', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jms-key-'));
    const keyPath = join(dir, 'id_ed25519');
    writeFileSync(keyPath, 'PRIVATE KEY BODY');
    const config = loadConfig({ ...baseEnv, JMS_SSH_PASSWORD: '', JMS_SSH_PRIVATE_KEY_PATH: keyPath });
    const profile = resolveBastion(config, null, {});
    assert.equal(profile.privateKey, 'PRIVATE KEY BODY');
});

test('the host whitelist comes from the environment and is empty by default', () => {
    assert.deepEqual(loadConfig(baseEnv).defaults.hostWhitelist, []);
    const { defaults } = loadConfig({ ...baseEnv, JMS_SSH_HOST_WHITELIST: '10.0.0.1, db-01' });
    assert.deepEqual(defaults.hostWhitelist, ['10.0.0.1', 'db-01']);
});

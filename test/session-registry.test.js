import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The tool surface is the design: assert it from the source so a refactor cannot
// quietly push session bookkeeping back onto the agent.
const source = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
const sessionSource = readFileSync(new URL('../src/session.js', import.meta.url), 'utf8');

test('the agent names a host, not a session', () => {
    assert.match(source, /registerTool\('jms_ssh_run'/);
    // One execution tool is the whole command surface: no second way in.
    assert.doesNotMatch(source, /registerTool\('jms_logs'/);
    assert.doesNotMatch(source, /registerTool\('jms_ssh_spool_read'/);
    // No tool input ever asks the caller for a session identifier.
    assert.doesNotMatch(source, /sessionId: z\./);
});

test('every result is plain json the model can read', () => {
    assert.match(source, /const json = payload => \(\{ content: \[\{ type: 'text', text: fitToBudget\(payload\) \}\] \}\)/);
    assert.match(source, /exitCode: run\.exitCode/);
    assert.match(source, /output: clean\.text/);
});

test('connections are keyed by host and opened once', () => {
    assert.match(source, /const byHost = new Map\(\)/);
    assert.match(source, /const connecting = new Map\(\)/);
    assert.match(source, /if \(connecting\.has\(key\)\) return connecting\.get\(key\)/);
});

test('host aliases map id, IP and hostname to one connection', () => {
    assert.match(source, /for \(const alias of session\.assetAliases\)/);
});

test('connections are evicted least-recently-used beyond the cap', () => {
    assert.match(source, /function evictIfNeeded/);
    assert.match(source, /sort\(\(a, b\) => a\.lastActivity - b\.lastActivity\)/);
});

test('output is bounded in the session, not accumulated', () => {
    assert.match(sessionSource, /new OutputWindow\(/);
    assert.match(sessionSource, /this\.window\.append\(/);
    assert.doesNotMatch(sessionSource, /\+\$?= text;/);
});

test('a command that outlives its timeout is interrupted', () => {
    assert.match(sessionSource, /\\u0003/);
    assert.match(sessionSource, /interrupted with Ctrl-C/);
});
test('a reply is capped by serialized bytes, not by field length', () => {
    assert.match(source, /JMS_SSH_MAX_RESULT_BYTES/);
    assert.match(source, /function fitToBudget/);
    assert.match(source, /Buffer\.byteLength\(text\) <= MAX_RESULT_BYTES/);
    // truncateOutput returns a record; the budget pass must use its text.
    assert.match(source, /truncateOutput\(body, Math\.max\(256, targetChars\)\)\.text/);
});

test('binary output cannot inflate the reply six-fold', () => {
    const utilSource = readFileSync(new URL('../src/util.js', import.meta.url), 'utf8');
    assert.match(utilSource, /export function sanitizeForJson/);
    assert.match(source, /sanitizeForJson\(run\.output\)/);
});

test('every attempt is audited from the tool itself', () => {
    assert.match(source, /const AUDIT_LOG = config\.defaults\.auditLog/);
    assert.match(source, /outcome: 'refused'/);
    assert.match(source, /outcome: 'ok'/);
    assert.match(source, /appendFileSync\(AUDIT_LOG/);
    // Output text is opt-in: logs leak secrets more often than they help.
    const configSource = readFileSync(new URL('../src/config.js', import.meta.url), 'utf8');
    assert.match(configSource, /JMS_SSH_AUDIT_OUTPUT/);
});

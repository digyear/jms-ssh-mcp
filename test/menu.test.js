import test from 'node:test';
import assert from 'node:assert/strict';
import { parseAssetList, parsePageInfo } from '../src/menu.js';
import { stripAnsi, truncateOutput, decodeEnterKey, redact, tail } from '../src/util.js';

test('parses a JumpServer asset listing', () => {
    const listing = [
        '  ID | \u540D\u79F0          | \u5730\u5740            | \u534F\u8BAE  | \u5E73\u53F0  | \u7EC4\u7EC7  | \u5907\u6CE8',
        '-----+---------------+-----------------+-------+-------+-------+------',
        '  1  | db-01   | 10.0.0.11 | s...p | Linux | D...t |',
        '  104 | web-01  | 10.0.0.15 | s...p | Linux | D...t | Test box',
        '\u9875\u7801\uFF1A1\uFF0C\u6BCF\u9875\u884C\u6570\uFF1A42\uFF0C\u603B\u9875\u6570\uFF1A2\uFF0C\u603B\u6570\u91CF\uFF1A48',
        '[Host]> ',
    ].join('\r\n');
    const assets = parseAssetList(listing);
    assert.equal(assets.length, 2);
    assert.deepEqual(assets[1], {
        id: 104,
        name: 'web-01',
        ip: '10.0.0.15',
        protocol: 's...p',
        platform: 'Linux',
        org: 'D...t',
        note: 'Test box',
    });
});

test('reads the page footer', () => {
    assert.deepEqual(parsePageInfo('\u9875\u7801\uFF1A1\uFF0C\u6BCF\u9875\u884C\u6570\uFF1A42\uFF0C\u603B\u9875\u6570\uFF1A2\uFF0C\u603B\u6570\u91CF\uFF1A48'), { pages: 2, total: 48 });
    assert.deepEqual(parsePageInfo('nothing here'), { pages: 1, total: null });
});

test('ignores menu lines that are not asset rows', () => {
    const menu = '1) \u8F93\u5165 \u90E8\u5206IP\uFF0C\u4E3B\u673A\u540D\uFF0C\u5907\u6CE8 \u8FDB\u884C\u641C\u7D22\u767B\u5F55(\u5982\u679C\u552F\u4E00).\r\n2) \u8F93\u5165 / + IP\r\nOpt> ';
    assert.deepEqual(parseAssetList(menu), []);
});

test('strips ANSI and carriage returns', () => {
    assert.equal(stripAnsi('\x1b[5D\x1b[KOpt> \r'), 'Opt> ');
});

test('truncates from both ends', () => {
    const { text, truncated } = truncateOutput('a'.repeat(100) + 'b'.repeat(100), 60);
    assert.equal(truncated, true);
    assert.match(text, /truncated 140 bytes/);
    assert.ok(text.startsWith('aaaa'));
    assert.ok(text.endsWith('bbbb'));
});

test('decodes enter key settings', () => {
    assert.equal(decodeEnterKey('cr'), '\r');
    assert.equal(decodeEnterKey('lf'), '\n');
    assert.equal(decodeEnterKey('13'), '\r');
    assert.equal(decodeEnterKey(undefined), '\r');
});

test('redacts secrets in error text', () => {
    assert.equal(redact('auth failed for hunter2secret', ['hunter2secret']), 'auth failed for ***');
});
test('error tails drop binary noise', () => {
    assert.equal(tail('abc\u0000\u0000\u001b[5Ddef\n\n ghi', 100), 'abcdef ghi');
});

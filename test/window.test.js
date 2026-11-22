import test from 'node:test';
import assert from 'node:assert/strict';
import { OutputWindow } from '../src/window.js';

test('keeps memory flat while a command floods output', () => {
    const window = new OutputWindow({ maxChars: 10000 });
    const chunk = 'x'.repeat(1000);
    for (let i = 0; i < 5000; i += 1) window.append(chunk);
    assert.ok(window.length <= 10000, `window kept ${window.length} chars`);
    assert.equal(window.droppedChars, 5_000_000 - window.length);
    assert.equal(window.totalChars, 5_000_000);
});

test('keeps a head and the newest output', () => {
    const window = new OutputWindow({ maxChars: 100, headChars: 20, tailChars: 80 });
    window.append('BEGIN'.padEnd(20, '-'));
    window.append('y'.repeat(500));
    window.append('LAST');
    const text = window.text();
    assert.ok(text.startsWith('BEGIN'));
    assert.ok(text.trimEnd().endsWith('LAST'));
    assert.match(text, /chars dropped/);
    assert.ok(text.length < 200, `materialized ${text.length} chars`);
});

test('the delta feed is bounded for progress streaming', () => {
    const window = new OutputWindow({ maxChars: 1000 });
    window.append('a'.repeat(10000));
    const delta = window.takeDelta();
    assert.ok(delta.length <= 4096);
    assert.equal(window.takeDelta(), '');
});

test('under the cap nothing is dropped', () => {
    const window = new OutputWindow({ maxChars: 1000 });
    window.append('hello\n');
    window.append('world\n');
    assert.equal(window.text(), 'hello\nworld\n');
    assert.equal(window.droppedChars, 0);
});
test('short output is visible through tail', () => {
    const window = new OutputWindow({ maxChars: 4 << 20 });
    window.append('Opt> ');
    assert.equal(window.tail(80), 'Opt> ');
    assert.equal(window.length, 5);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { totp, parseOtpAuthUri, secondsRemaining } from '../src/totp.js';

// RFC 6238 appendix B seed, truncated to the 6 digits authenticator apps use.
const RFC_SEED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('matches the RFC 6238 vectors at 6 digits', () => {
    assert.equal(totp(RFC_SEED, { now: 59_000 }), '287082');
    assert.equal(totp(RFC_SEED, { now: 1_111_111_109_000 }), '081804');
    assert.equal(totp(RFC_SEED, { now: 2_000_000_000_000 }), '279037');
});

test('accepts lowercase and spaced seeds', () => {
    assert.equal(totp('gezd gnbv gy3t qojq gezd gnbv gy3t qojq', { now: 59_000 }), '287082');
});

test('rejects characters outside base32', () => {
    assert.throws(() => totp('NOT_BASE32!', { now: 0 }), /invalid base32/);
});

test('rolls over on the step boundary', () => {
    assert.notEqual(totp(RFC_SEED, { now: 29_000 }), totp(RFC_SEED, { now: 31_000 }));
    assert.equal(secondsRemaining({ now: 0 }), 30);
});

test('parses an otpauth:// URI', () => {
    const parsed = parseOtpAuthUri('otpauth://totp/JumpServer:alice?secret=JBSWY3DPEHPK3PXP&issuer=JumpServer&digits=6&period=30');
    assert.equal(parsed.secret, 'JBSWY3DPEHPK3PXP');
    assert.equal(parsed.label, 'JumpServer:alice');
    assert.equal(parsed.issuer, 'JumpServer');
});
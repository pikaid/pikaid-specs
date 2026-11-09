#!/usr/bin/env node
/**
 * Independent second-language oracle for PikaID deterministic vectors.
 * It uses Node.js BigInt and Buffer rather than the Python verifier's
 * conversion routines. It does not exercise a production PikaID library.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (suite) => JSON.parse(readFileSync(join(root, 'cases', `${suite}.json`), 'utf8')).cases;
const maxTs = 36n ** 7n - 1n;
const maxEntropy = 2n ** 96n - 1n;
const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';

function decode36(s) {
  let acc = 0n;
  for (const digit of s) {
    const value = alphabet.indexOf(digit);
    if (value < 0) throw Error('invalid Base36 digit');
    acc = acc * 36n + BigInt(value);
  }
  return acc;
}
function encode36(number, width) {
  return number.toString(36).padStart(width, '0');
}
function binary(ts, entropy) {
  if (ts < 0n || ts > maxTs || entropy.length !== 12) throw Error('invalid component');
  const prefix = Buffer.alloc(5);
  let value = ts;
  for (let i = 4; i >= 0; --i) {
    prefix[i] = Number(value & 255n);
    value >>= 8n;
  }
  return Buffer.concat([prefix, entropy]);
}
function textToBinary(text) {
  if (typeof text !== 'string' || !/^[0-9a-z]{26}$/.test(text)) throw Error('invalid text');
  const ts = decode36(text.slice(0, 7));
  const rand = decode36(text.slice(7));
  if (ts > maxTs || rand > maxEntropy) throw Error('value overflow');
  const entropy = Buffer.alloc(12);
  let value = rand;
  for (let i = 11; i >= 0; --i) {
    entropy[i] = Number(value & 255n);
    value >>= 8n;
  }
  return binary(ts, entropy);
}
function binaryToText(buf) {
  if (!Buffer.isBuffer(buf) || buf.length !== 17) throw Error('invalid binary length');
  let ts = 0n;
  for (const byte of buf.subarray(0, 5)) ts = (ts << 8n) | BigInt(byte);
  if (ts > maxTs) throw Error('binary timestamp overflow');
  const rand = BigInt(`0x${buf.subarray(5).toString('hex')}`);
  return encode36(ts, 7) + encode36(rand, 19);
}
function cmp(a,b) {
  return Math.sign(Buffer.compare(a,b));
}
function main() {
  let counts = { valid: 0, invalidString: 0, invalidBinary: 0, ordering: 0 };
  for (const c of read('valid')) {
    const expected = binary(BigInt(c.timestamp_seconds), Buffer.from(c.randomness_hex, 'hex'));
    assert.equal(c.binary_hex, expected.toString('hex'), c.id);
    assert.equal(c.pikaid, binaryToText(expected), c.id);
    assert.equal(textToBinary(c.pikaid).toString('hex'), c.binary_hex, c.id);
    counts.valid++;
  }
  for (const c of read('invalid-string')) {
    assert.throws(() => textToBinary(c.input), Error, c.id);
    counts.invalidString++;
  }
  for (const c of read('invalid-binary')) {
    assert.throws(() => binaryToText(Buffer.from(c.input_hex,'hex')), Error, c.id);
    counts.invalidBinary++;
  }
  for (const c of read('ordering')) {
    const ba = textToBinary(c.a_pikaid);
    const bb = textToBinary(c.b_pikaid);
    assert.equal(ba.toString('hex'), c.a_binary_hex, c.id);
    assert.equal(bb.toString('hex'), c.b_binary_hex, c.id);
    assert.equal(cmp(ba,bb), c.expected_compare, c.id);
    assert.equal(cmp(Buffer.from(c.a_pikaid,'ascii'),Buffer.from(c.b_pikaid,'ascii')),
                 c.expected_compare, c.id);
    counts.ordering++;
  }
  assert.deepEqual([maxTs.toString(), maxEntropy.toString()],
                   ['78364164095','79228162514264337593543950335']);
  console.log(`PASS: independent Node.js BigInt oracle ${JSON.stringify(counts)}`);
}
main();

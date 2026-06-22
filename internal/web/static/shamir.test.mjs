// Unit tests for the browser Shamir implementation, run with `node --test`.
// Web Crypto (crypto.subtle, crypto.getRandomValues), btoa, and atob are global
// in Node 20+, so shamir.js loads unchanged.
import { test } from "node:test";
import assert from "node:assert/strict";
import { split, combine, tokenToRaw, rawToToken } from "./shamir.js";

const text = (bytes) => new TextDecoder().decode(bytes);
const bytes = (str) => new TextEncoder().encode(str);

test("split/combine round-trips for several n,k", async () => {
  for (const [n, k] of [[2, 2], [3, 2], [5, 3], [10, 7]]) {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const shares = await split(secret, n, k);
    assert.equal(shares.length, n);
    const got = await combine(shares);
    assert.deepEqual(got, secret, `n=${n} k=${k}`);
  }
});

test("any k-of-n subset reconstructs", async () => {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const shares = await split(secret, 5, 3);
  const subsets = [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]];
  for (const sub of subsets) {
    const got = await combine(sub.map((i) => shares[i]));
    assert.deepEqual(got, secret, `subset ${sub}`);
  }
});

// Interop: this exact vector is also asserted by the Go test
// TestCombineFixedVector, proving the JS and Go sss1. encodings agree.
test("interoperates with the Go encoding (fixed vector)", async () => {
  const shares = [
    "sss1.3.1.FGUNgA.kpGnNgOFuHoiusJeocz3Zifs6k1MPqVgi8EPlCtA6jg",
    "sss1.3.3.fcHiSg.-P3y1aaZ0hREMHWEiWs_CtyvNl5EZc4NI8PHtOYs_Bk",
    "sss1.3.5.ZRqVhw.kpWGYlM6w1u93zJPGwSNFbPPjvqRpzCbuUzUpcUIijg",
  ];
  const got = await combine(shares);
  assert.equal(text(got), "0123456789abcdef0123456789abcdef");
});

test("rejects too few shares and corrupted shares", async () => {
  const shares = await split(bytes("hello shamir!!"), 5, 3);
  await assert.rejects(() => combine(shares.slice(0, 2)), /not enough shares/);

  // Corrupt the first body byte so the checksum no longer matches. We change
  // the first base64 char of the body, which carries real data bits; the last
  // char's low bits are encoding padding and flipping them can be a no-op.
  const parts = shares[0].split(".");
  const body = parts[parts.length - 1];
  parts[parts.length - 1] = (body[0] === "A" ? "B" : "A") + body.slice(1);
  await assert.rejects(() => combine([parts.join("."), shares[1], shares[2]]), /checksum/);

  await assert.rejects(() => combine(["garbage", shares[1], shares[2]]), /malformed/);
});

test("token <-> raw round-trips and splits", async () => {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = rawToToken(raw);
  assert.ok(token.startsWith("ss."));
  assert.deepEqual(tokenToRaw(token), raw);

  // The real flow: split a token's raw bytes, then reconstruct the token.
  const shares = await split(raw, 4, 2);
  const reconstructed = rawToToken(await combine([shares[1], shares[3]]));
  assert.equal(reconstructed, token);
});

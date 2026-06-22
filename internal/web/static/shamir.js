// Browser-side Shamir secret sharing over GF(2^8), wire-compatible with the Go
// implementation in internal/shamir. It splits/reconstructs the 32-byte wrap
// token entirely in the browser so the server never sees a share.
//
// Share strings use the same self-describing format as the CLI:
//   sss1.<k>.<x>.<chk>.<base64url(body)>
//
// This file is an ES module: the browser loads it via dynamic import() and the
// node --test suite imports it directly, so one implementation is shared and
// tested. Unlike the Go version it is not written to be constant-time; timing
// side-channels against a user's own token in their own browser are out of
// scope.

const SHARE_PREFIX = "sss1.";
const SHARE_VERSION = 1;
const CHECKSUM_LEN = 4;

// --- GF(2^8) arithmetic (AES field, modulus 0x11b) ---

function gfMul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}

// gfInv returns a^-1 as a^254 (the multiplicative group has order 255).
function gfInv(a) {
  let result = 1;
  let base = a;
  for (let exp = 254; exp > 0; exp >>= 1) {
    if (exp & 1) result = gfMul(result, base);
    base = gfMul(base, base);
  }
  return result;
}

// gfEval evaluates a polynomial (coeffs[0] is the constant term) at x.
function gfEval(coeffs, x) {
  let y = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) y = gfMul(y, x) ^ coeffs[i];
  return y & 0xff;
}

// --- core split / combine on raw body||x byte arrays ---

function splitRaw(secret, n, k) {
  const shares = [];
  for (let i = 0; i < n; i++) {
    const s = new Uint8Array(secret.length + 1);
    s[secret.length] = i + 1; // x-coordinate, never 0
    shares.push(s);
  }
  const coeffs = new Uint8Array(k);
  for (let bi = 0; bi < secret.length; bi++) {
    coeffs[0] = secret[bi];
    crypto.getRandomValues(coeffs.subarray(1));
    for (let i = 0; i < n; i++) {
      shares[i][bi] = gfEval(coeffs, shares[i][secret.length]);
    }
  }
  return shares;
}

// combineRaw reconstructs via Lagrange interpolation at x=0. In GF(2^8)
// subtraction is XOR and negation is the identity.
function combineRaw(shares) {
  const bodyLen = shares[0].length - 1;
  const xs = shares.map((s) => s[bodyLen]);
  const secret = new Uint8Array(bodyLen);
  for (let bi = 0; bi < bodyLen; bi++) {
    let acc = 0;
    for (let i = 0; i < shares.length; i++) {
      let num = 1;
      let den = 1;
      for (let j = 0; j < shares.length; j++) {
        if (j === i) continue;
        num = gfMul(num, xs[j]);
        den = gfMul(den, xs[i] ^ xs[j]);
      }
      const basis = gfMul(num, gfInv(den));
      acc ^= gfMul(shares[i][bi], basis);
    }
    secret[bi] = acc;
  }
  return secret;
}

// --- base64url + checksum + encoding ---

function b64urlEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function shareChecksum(k, x, body) {
  const buf = new Uint8Array(3 + body.length);
  buf[0] = SHARE_VERSION;
  buf[1] = k;
  buf[2] = x;
  buf.set(body, 3);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return digest.slice(0, CHECKSUM_LEN);
}

async function encodeShare(k, x, body) {
  const chk = await shareChecksum(k, x, body);
  return `${SHARE_PREFIX}${k}.${x}.${b64urlEncode(chk)}.${b64urlEncode(body)}`;
}

async function decodeShare(s) {
  if (!s.startsWith(SHARE_PREFIX)) throw new Error("malformed share");
  const parts = s.slice(SHARE_PREFIX.length).split(".");
  if (parts.length !== 4) throw new Error("malformed share");
  if (!/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])) throw new Error("malformed share");
  const k = parseInt(parts[0], 10);
  const x = parseInt(parts[1], 10);
  if (k < 2 || k > 255 || x < 1 || x > 255) throw new Error("malformed share");
  let chk, body;
  try {
    chk = b64urlDecode(parts[2]);
    body = b64urlDecode(parts[3]);
  } catch {
    throw new Error("malformed share");
  }
  if (chk.length !== CHECKSUM_LEN || body.length === 0) throw new Error("malformed share");
  if (!bytesEqual(chk, await shareChecksum(k, x, body))) {
    throw new Error("a share failed its checksum (corrupted or mistyped)");
  }
  return { k, x, body };
}

// --- public API ---

// split divides a secret (Uint8Array) into n shares, any k reconstructing it.
export async function split(secret, n, k) {
  if (secret.length === 0) throw new Error("secret is empty");
  if (k < 2 || k > n) throw new Error("threshold must satisfy 2 <= k <= n");
  if (n > 255) throw new Error("number of shares exceeds 255");
  const raw = splitRaw(secret, n, k);
  const out = [];
  for (const s of raw) {
    out.push(await encodeShare(k, s[s.length - 1], s.subarray(0, s.length - 1)));
  }
  return out;
}

// combine validates and reconstructs the secret (Uint8Array) from k or more
// encoded shares.
export async function combine(shareStrings) {
  if (shareStrings.length < 2) throw new Error("not enough shares to reconstruct");
  let wantK = null;
  let bodyLen = null;
  const seen = new Set();
  const raw = [];
  for (const str of shareStrings) {
    const { k, x, body } = await decodeShare(str.trim());
    if (wantK === null) {
      wantK = k;
      bodyLen = body.length;
    } else if (k !== wantK) {
      throw new Error("shares disagree on threshold");
    } else if (body.length !== bodyLen) {
      throw new Error("shares differ in length");
    }
    if (seen.has(x)) throw new Error("duplicate share coordinate");
    seen.add(x);
    const point = new Uint8Array(bodyLen + 1);
    point.set(body);
    point[bodyLen] = x;
    raw.push(point);
  }
  if (raw.length < wantK) throw new Error("not enough shares to reconstruct");
  return combineRaw(raw);
}

// tokenToRaw decodes an "ss." wrap token into its 32 raw bytes.
export function tokenToRaw(token) {
  if (!token.startsWith("ss.")) throw new Error("not a secretstash token");
  const raw = b64urlDecode(token.slice(3));
  if (raw.length !== 32) throw new Error("not a secretstash token");
  return raw;
}

// rawToToken renders raw token bytes back to the "ss." form.
export function rawToToken(raw) {
  return "ss." + b64urlEncode(raw);
}

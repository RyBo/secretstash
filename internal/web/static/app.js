"use strict";

// Shared by index.html (create), s.html (unwrap), and combine.html (combine).
// The unwrap token lives in location.hash: browsers never send the fragment to
// any server, so share links leak nothing into logs or previews. Shamir shares
// are pasted on /combine and reconstructed in-browser; only the rebuilt token
// is ever sent to the server.

const $ = (id) => document.getElementById(id);

async function apiFetch(path, opts = {}) {
  const resp = await fetch(path, opts);
  let body = null;
  try { body = await resp.json(); } catch { /* 204 or empty */ }
  return { status: resp.status, body };
}

function show(id) { $(id).classList.remove("hidden"); }
function hide(id) { $(id).classList.add("hidden"); }
function hideIfPresent(id) { const el = $(id); if (el) el.classList.add("hidden"); }

function fmtExpiry(iso) {
  const ms = new Date(iso) - Date.now();
  if (ms <= 0) return "expired";
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  return h > 0 ? `expires in ${h}h ${m}m` : `expires in ${m}m`;
}

document.addEventListener("click", (e) => {
  const id = e.target.dataset?.copy;
  if (!id) return;
  const el = $(id);
  navigator.clipboard.writeText(el.value ?? el.textContent).then(() => {
    const btn = e.target;
    const prev = btn.textContent;
    btn.textContent = "Copied ✓";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = prev; btn.classList.remove("copied"); }, 1200);
  });
});

// --- about dialog (all pages) ---

const about = $("about");
if (about) {
  $("about-open")?.addEventListener("click", () => about.showModal());
  $("about-close")?.addEventListener("click", () => about.close());
  about.addEventListener("click", (e) => { if (e.target === about) about.close(); });
}

// --- shared reveal / gone renderers (unwrap + combine pages) ---

function renderGone(status, body) {
  hideIfPresent("waiting");
  hideIfPresent("combine");
  const code = body?.code;
  if (code === "consumed") {
    $("gone-msg").textContent = "This secret was already read.";
    $("gone-detail").textContent =
      `Final read occurred at ${new Date(body.consumed_at).toLocaleString()}. ` +
      "If that wasn't you, treat the secret as compromised and rotate it.";
  } else if (code === "expired") {
    $("gone-msg").textContent = "This secret expired before it was read.";
    $("gone-detail").textContent = body.message;
  } else if (code === "revoked") {
    $("gone-msg").textContent = "This secret was revoked by its creator.";
    $("gone-detail").textContent = body.message;
  } else {
    $("gone-msg").textContent = "No secret found.";
    $("gone-detail").textContent =
      "It may never have existed, or its record has aged out. Check the link or shares.";
  }
  show("gone");
}

function showSecret(body) {
  hideIfPresent("waiting");
  hideIfPresent("combine");
  $("secret").textContent = body.secret;
  $("revealed-meta").textContent =
    body.reads_remaining > 0
      ? `${body.reads_remaining} read${body.reads_remaining > 1 ? "s" : ""} remaining`
      : "That was the final read. The secret is now destroyed.";
  show("revealed");
}

// --- create flow (index.html) ---

if ($("wrap")) {
  const splitToggle = $("split-toggle");
  splitToggle?.addEventListener("change", () => {
    $("split-opts").classList.toggle("hidden", !splitToggle.checked);
  });

  const createError = (msg) => { $("create-error").textContent = msg; show("create-error"); };

  $("wrap").addEventListener("click", async () => {
    hide("create-error");
    const secret = $("secret").value;
    if (!secret) {
      createError("Enter a secret first.");
      return;
    }

    const splitMode = !!splitToggle?.checked;
    let n = 0, k = 0;
    if (splitMode) {
      n = parseInt($("shares").value, 10);
      k = parseInt($("threshold").value, 10);
      if (k > n) {
        createError("Required to unlock can't exceed the number of shares.");
        return;
      }
    }

    const { status, body } = await apiFetch("/v1/wrap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret, ttl: $("ttl").value, reads: parseInt($("reads").value, 10) }),
    });
    if (status !== 200) {
      createError(body?.message ?? `Error (${status})`);
      return;
    }
    $("secret").value = "";

    if (splitMode) {
      // Split the token in the browser; the whole token and single-link share
      // URL are never shown, since either alone would defeat the split.
      try {
        const shamir = await import("/static/shamir.js");
        const parts = await shamir.split(shamir.tokenToRaw(body.token), n, k);
        renderShares(parts, k);
      } catch (e) {
        createError("Could not split the secret: " + e.message);
        return;
      }
      hide("single-result");
      show("shares-result");
    } else {
      $("share-url").value = body.share_url || `${location.origin}/s#${body.token}`;
      $("token").value = body.token;
      show("single-result");
      hide("shares-result");
    }
    $("result-meta").textContent =
      `${body.reads} read${body.reads > 1 ? "s" : ""} · ${fmtExpiry(body.expires_at)}`;
    hide("create");
    show("result");
  });

  $("again").addEventListener("click", () => {
    $("share-url").value = $("token").value = "";
    $("shares-list").innerHTML = "";
    hide("result");
    show("create");
    $("secret").focus();
  });
}

function renderShares(parts, k) {
  $("quorum-text").textContent = `${k} of ${parts.length}`;
  const list = $("shares-list");
  list.innerHTML = "";
  parts.forEach((s, i) => {
    const id = `share-${i}`;
    const field = document.createElement("div");
    field.className = "copyfield";
    const input = document.createElement("input");
    input.readOnly = true;
    input.id = id;
    input.value = s;
    const btn = document.createElement("button");
    btn.dataset.copy = id;
    btn.textContent = "Copy";
    field.append(input, btn);
    list.append(field);
  });
}

// --- unwrap flow (s.html) ---

if ($("reveal")) {
  const token = location.hash.slice(1);

  const init = async () => {
    if (!token) {
      show("nolink");
      return;
    }
    // Non-consuming peek: page load must never burn a read, so link previews
    // and prefetchers can't destroy the secret.
    const { status, body } = await apiFetch("/v1/peek", {
      headers: { "X-Stash-Token": token },
    });
    if (status !== 200) {
      renderGone(status, body);
      return;
    }
    $("waiting-meta").textContent =
      `${body.reads_remaining} read${body.reads_remaining > 1 ? "s" : ""} remaining · ${fmtExpiry(body.expires_at)}`;
    show("waiting");
  };

  $("reveal").addEventListener("click", async () => {
    const { status, body } = await apiFetch("/v1/unwrap", {
      method: "POST",
      headers: { "X-Stash-Token": token },
    });
    if (status !== 200) {
      renderGone(status, body);
      return;
    }
    showSecret(body);
  });

  init();
}

// --- combine flow (combine.html) ---

if ($("combine-reveal")) {
  const combineError = (msg) => { $("combine-error").textContent = msg; show("combine-error"); };

  $("combine-reveal").addEventListener("click", async () => {
    hide("combine-error");
    const lines = $("shares-input").value.split("\n").map((s) => s.trim()).filter(Boolean);
    if (lines.length < 2) {
      combineError("Paste at least two shares, one per line.");
      return;
    }

    // Reconstruct entirely in the browser. A bad, insufficient, or corrupted
    // set of shares fails here, before anything is sent to the server.
    let token;
    try {
      const shamir = await import("/static/shamir.js");
      token = shamir.rawToToken(await shamir.combine(lines));
    } catch (e) {
      combineError(e.message);
      return;
    }

    const { status, body } = await apiFetch("/v1/unwrap", {
      method: "POST",
      headers: { "X-Stash-Token": token },
    });
    if (status !== 200) {
      renderGone(status, body);
      return;
    }
    showSecret(body);
  });
}

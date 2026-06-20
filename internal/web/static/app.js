"use strict";

// Shared by index.html (create flow) and s.html (unwrap flow).
// The unwrap token lives in location.hash: browsers never send the fragment
// to any server, so share links leak nothing into logs or previews.

const $ = (id) => document.getElementById(id);

async function apiFetch(path, opts = {}) {
  const resp = await fetch(path, opts);
  let body = null;
  try { body = await resp.json(); } catch { /* 204 or empty */ }
  return { status: resp.status, body };
}

function show(id) { $(id).classList.remove("hidden"); }
function hide(id) { $(id).classList.add("hidden"); }

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

// --- create flow (index.html) ---

if ($("wrap")) {
  $("wrap").addEventListener("click", async () => {
    hide("create-error");
    const secret = $("secret").value;
    if (!secret) {
      $("create-error").textContent = "Enter a secret first.";
      show("create-error");
      return;
    }
    const { status, body } = await apiFetch("/v1/wrap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret, ttl: $("ttl").value, reads: parseInt($("reads").value, 10) }),
    });
    if (status !== 200) {
      $("create-error").textContent = body?.message ?? `Error (${status})`;
      show("create-error");
      return;
    }
    $("secret").value = "";
    $("share-url").value = body.share_url || `${location.origin}/s#${body.token}`;
    $("token").value = body.token;
    $("result-meta").textContent =
      `${body.reads} read${body.reads > 1 ? "s" : ""} · ${fmtExpiry(body.expires_at)}`;
    hide("create");
    show("result");
  });

  $("again").addEventListener("click", () => {
    $("share-url").value = $("token").value = "";
    hide("result");
    show("create");
    $("secret").focus();
  });
}

// --- unwrap flow (s.html) ---

if ($("reveal")) {
  const token = location.hash.slice(1);

  const renderGone = (status, body) => {
    hide("waiting");
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
      $("gone-msg").textContent = "No secret found for this link.";
      $("gone-detail").textContent =
        "It may never have existed, or its record has aged out. Check you copied the full link.";
    }
    show("gone");
  };

  const init = async () => {
    if (!token) {
      show("nolink");
      return;
    }
    // Non-consuming peek: page load must never burn a read, so link
    // previews and prefetchers can't destroy the secret.
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
    hide("waiting");
    $("secret").textContent = body.secret;
    $("revealed-meta").textContent =
      body.reads_remaining > 0
        ? `${body.reads_remaining} read${body.reads_remaining > 1 ? "s" : ""} remaining`
        : "That was the final read. The secret is now destroyed.";
    show("revealed");
  });

  init();
}

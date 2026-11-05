import assert from "node:assert/strict";
import { test } from "node:test";
import vm from "node:vm";
import { renderLogin } from "../login.mjs";

function client(fetchImpl) {
  const elements = {
    input: { value: "test-secret" },
    button: { disabled: false },
    "[role=status]": { textContent: "" },
    form: { addEventListener: (_event, handler) => { elements.submit = handler; } },
  };
  const navigation = [];
  const html = renderLogin("test-nonce", "/threads/thread-1?panel=files");
  const script = /<script nonce="test-nonce">([\s\S]*?)<\/script>/u.exec(html)[1];
  vm.runInNewContext(script, {
    document: { querySelector: (selector) => elements[selector] },
    fetch: fetchImpl,
    location: { replace: (path) => navigation.push(path) },
    AbortSignal,
  });
  return { elements, navigation, html, submit: () => elements.submit({ preventDefault() {} }) };
}

test("login client sends a single same-origin POST and returns to the deep link", async () => {
  let finish;
  const calls = [];
  const c = client((...args) => {
    calls.push(args);
    return new Promise((resolve) => { finish = resolve; });
  });
  const first = c.submit();
  assert.equal(c.elements.input.value, "");
  assert.equal(c.elements.button.disabled, true);
  await c.submit();
  assert.equal(calls.length, 1);
  const [path, request] = calls[0];
  assert.equal(path, "/office/login");
  assert.equal(request.method, "POST");
  assert.equal(request.mode, "same-origin");
  assert.equal(request.redirect, "error");
  assert.equal(request.credentials, "same-origin");
  assert.equal(JSON.parse(request.body).token, "test-secret");
  assert.equal(request.signal instanceof AbortSignal, true);
  finish({ ok: true, status: 200 });
  await first;
  assert.deepEqual(c.navigation, ["/threads/thread-1?panel=files"]);
  assert.equal(c.elements.button.disabled, false);
  assert.ok(!c.html.includes("test-secret"));
});

test("offline login is retryable and never retains the key in the input", async () => {
  const c = client(async () => { throw new Error("offline"); });
  await c.submit();
  assert.equal(c.elements.input.value, "");
  assert.equal(c.elements.button.disabled, false);
  assert.match(c.elements["[role=status]"].textContent, /соединение/u);
  assert.deepEqual(c.navigation, []);
});

test("a denied or unavailable login never navigates to a protected page", async () => {
  for (const status of [401, 403, 503]) {
    const c = client(async () => ({ ok: false, status }));
    await c.submit();
    assert.deepEqual(c.navigation, []);
    assert.equal(c.elements.button.disabled, false);
    assert.equal(c.elements.input.value, "");
    assert.match(c.elements["[role=status]"].textContent, status === 503 ? /временно/u : /отклонён/u);
  }
});

test("script-disabled form never puts the key in a GET URL", () => {
  const c = client(async () => ({ ok: true, status: 200 }));
  assert.match(c.html, /<form method="post" action="\/office\/login">/u);
  assert.match(c.html, /initial-scale=1/u);
  assert.match(c.html, /font:16px/u);
  assert.match(c.html, /min-height:48px/u);
  assert.match(c.html, /aria-live="polite"/u);
});

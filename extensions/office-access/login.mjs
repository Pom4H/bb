import { canonicalPath } from "./policy.mjs";

export function isPagePath(path) {
  return !/^\/(?:api|internal|office|ws|health|install)(?:\/|$)/u.test(path) && !/^\/install\.(?:sh|ps1)$/u.test(path);
}

export function isDocumentNavigation(request) {
  return request.method === "GET"
    && request.headers.accept?.split(",").some((item) => item.trim().split(";", 1)[0] === "text/html") === true
    && [undefined, "navigate"].includes(request.headers["sec-fetch-mode"])
    && [undefined, "document"].includes(request.headers["sec-fetch-dest"])
    && request.headers.authorization === undefined
    && request.headers["x-auth-request-user"] === undefined
    && request.headers["x-bb-auth-proxy-key"] === undefined;
}

function destination(value) {
  if (typeof value !== "string" || value.length > 4096 || !isPagePath(canonicalPath(value))) {
    throw new Error("Invalid login return target");
  }
  return value;
}

export function loginLocation(target) {
  const next = destination(target);
  return next === "/" ? "/office/login" : `/office/login?${new URLSearchParams({ next })}`;
}

export function loginDestination(target) {
  const params = new URL(target, "https://office.invalid").searchParams;
  if (params.size === 0) return "/";
  if (params.size !== 1 || !params.has("next")) throw new Error("Invalid login parameters");
  return destination(params.get("next"));
}

export function renderLogin(nonce, next) {
  const returnTo = JSON.stringify(destination(next)).replace(/</gu, "\\u003c").replace(/\u2028/gu, "\\u2028").replace(/\u2029/gu, "\\u2029");
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>bb · Вход</title>
<style nonce="${nonce}">
:root{color-scheme:light dark;--canvas:Canvas;--ink:CanvasText}
*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font:16px/1.5 system-ui,sans-serif}
main{max-width:28rem;margin:8vh auto;padding:max(1.5rem,env(safe-area-inset-top)) max(1.5rem,env(safe-area-inset-right)) max(1.5rem,env(safe-area-inset-bottom)) max(1.5rem,env(safe-area-inset-left))}
h1{font-size:1.75rem}label{display:block}input,button{width:100%;min-height:48px;font:inherit;border-radius:.5rem;padding:.75rem;margin-top:.5rem}
input{background:var(--canvas);color:var(--ink);border:1px solid color-mix(in oklab,var(--ink) 35%,transparent)}button{background:var(--ink);color:var(--canvas);border:0;margin-top:1rem;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}:focus-visible{outline:3px solid Highlight;outline-offset:3px}[role=status]{min-height:3rem}
</style></head><body><main><h1>Вход в bb</h1>
<p>Введите персональный ключ доступа. Его выдаёт администратор.</p>
<form method="post" action="/office/login"><label for="token">Ключ доступа</label>
<input id="token" name="token" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" required>
<button type="submit">Войти</button></form><p role="status" aria-live="polite"></p></main>
<script nonce="${nonce}">
const returnTo = ${returnTo};
const form = document.querySelector('form');
const input = document.querySelector('input');
const button = document.querySelector('button');
const status = document.querySelector('[role=status]');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (button.disabled) return;
  const token = input.value;
  input.value = '';
  button.disabled = true;
  status.textContent = 'Выполняется вход…';
  try {
    const response = await fetch('/office/login', {
      method: 'POST', mode: 'same-origin', credentials: 'same-origin', redirect: 'error',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token }),
      signal: AbortSignal.timeout(15000),
    });
    if (response.ok) location.replace(returnTo);
    else status.textContent = response.status === 503
      ? 'Вход временно недоступен. Попробуйте позже.'
      : 'Вход отклонён. Проверьте ключ или обратитесь к администратору.';
  } catch {
    status.textContent = 'Не удалось связаться с сервером. Проверьте соединение и повторите вход.';
  } finally {
    button.disabled = false;
  }
});
</script></body></html>`;
}

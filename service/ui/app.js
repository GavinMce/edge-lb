'use strict';

// No framework, no build step. All data is inserted with textContent / text nodes,
// never innerHTML, so route names and error strings can't inject markup.

const $ = (sel) => document.querySelector(sel);

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

// ---- API --------------------------------------------------------------------------------

class ApiError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details || [];
  }
}

const TOKEN_KEY = 'edge-lb-token';
let token = '';
try { token = sessionStorage.getItem(TOKEN_KEY) || ''; } catch (_) { /* storage blocked */ }

async function api(method, path, body) {
  const used = token;
  const headers = { Authorization: 'Bearer ' + used };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch('/api' + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) {
    // Ignore a stale rejection: the user may have entered a new token while this was in flight.
    if (used === token) showLogin(used !== '');
    throw new ApiError(401, 'Unauthorized');
  }
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || res.statusText, data && data.details);
  return data;
}

// ---- formatting -------------------------------------------------------------------------

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(n >= 100 ? 0 : 1)) + ' ' + u[i];
}
function fmtUptime(s) {
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : m ? `${m}m` : `${s}s`;
}
const addr = (ip, port) => (ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`);

// ---- rendering --------------------------------------------------------------------------

let current = [];

function stateDot(r) {
  const s = r.status.state;
  if (s === 'listening') {
    const t = r.status.targets;
    const down = t.filter((x) => x.healthy === false).length;
    if (down === t.length) return ['bad', 'Listening, but every target is down'];
    if (down > 0) return ['warn', `Listening, ${down} of ${t.length} targets down`];
    return ['ok', 'Listening'];
  }
  if (s === 'error') return ['bad', 'Cannot listen: ' + (r.status.error || '')];
  if (s === 'disabled') return ['', 'Disabled'];
  return ['warn', 'Starting'];
}

function routeCard(r) {
  const [cls, title] = stateDot(r);
  const st = r.status;
  const domains = r.domains.length
    ? r.domains.map((d) => h('span', { class: 'chip mono' }, d))
    : [h('span', { class: 'chip any' }, 'everything on this port')];

  return h('div', { class: 'route' + (r.enabled ? '' : ' disabled'), 'data-id': r.id },
    h('div', { class: 'cell' },
      h('div', { class: 'name' }, h('span', { class: 'dot ' + cls, title }), r.name),
      h('div', { class: 'sub mono' }, r.id),
      st.error && h('div', { class: 'err' }, st.error),
    ),
    h('div', { class: 'cell' }, h('span', { class: 'label' }, 'Domains'), h('div', { class: 'chips' }, domains)),
    h('div', { class: 'cell' },
      h('span', { class: 'label' }, 'Listen'),
      h('div', { class: 'mono' }, addr(r.listen.ip, r.listen.port)),
      r.proxy_protocol && h('div', { class: 'chips' }, h('span', { class: 'chip flag' }, 'PROXY v2')),
    ),
    h('div', { class: 'cell' },
      h('span', { class: 'label' }, 'Targets'),
      h('div', { class: 'targets' }, st.targets.map((t) => {
        const c = t.healthy === true ? 'ok' : t.healthy === false ? 'bad' : '';
        const tip = t.healthy === true ? 'Healthy' : t.healthy === false ? 'Unreachable' : 'Not checked (route disabled)';
        return h('div', { class: 'target' },
          h('span', { class: 'dot ' + c, title: tip }),
          h('span', { class: 'mono' }, addr(t.address, t.port)),
          t.healthy === false && t.last_error && h('span', { class: 'why' }, t.last_error),
        );
      })),
    ),
    h('div', { class: 'cell' },
      h('span', { class: 'label' }, 'Traffic'),
      h('div', null, `${st.active_connections} active · ${st.total_connections} total`),
      h('div', { class: 'sub' }, `↑ ${fmtBytes(st.bytes_up)}  ↓ ${fmtBytes(st.bytes_down)}`),
      st.connect_failures > 0 && h('div', { class: 'sub' }, `${st.connect_failures} connect failures`),
    ),
    h('div', { class: 'row-actions' },
      h('button', { class: 'small', type: 'button', onclick: () => toggle(r) }, r.enabled ? 'Disable' : 'Enable'),
      h('button', { class: 'small', type: 'button', onclick: () => openEditor(r) }, 'Edit'),
      h('button', { class: 'small danger', type: 'button', onclick: () => remove(r) }, 'Delete'),
    ),
  );
}

function render(status) {
  current = status.routes;
  $('#summary').replaceChildren(
    h('span', { class: 'stat' }, h('b', null, status.routes.length), ' routes'),
    h('span', { class: 'stat' }, h('b', null, status.listeners), ' listeners'),
    h('span', { class: 'stat' }, h('b', null, status.active_connections), ' connections'),
    h('span', { class: 'stat' }, 'up ', h('b', null, fmtUptime(status.uptime_secs))),
    h('span', { class: 'stat' }, 'v', status.version),
  );

  const banner = $('#banner');
  if (status.firewall_error) {
    banner.className = 'banner';
    banner.textContent = 'Firewall sync failed: ' + status.firewall_error + ' New ports may be blocked.';
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }

  const sorted = [...status.routes].sort((a, b) =>
    a.listen.port - b.listen.port || a.listen.ip.localeCompare(b.listen.ip) || a.name.localeCompare(b.name));
  $('#routes').replaceChildren(...sorted.map(routeCard));
  $('#empty').hidden = sorted.length > 0;
}

// ---- polling ----------------------------------------------------------------------------

let timer = null;
async function refresh() {
  try {
    render(await api('GET', '/status'));
    $('#conn').className = 'conn ok';
    $('#conn').title = 'Connected';
  } catch (e) {
    $('#conn').className = 'conn bad';
    $('#conn').title = e.status === 401 ? 'Not signed in' : 'Cannot reach the service';
  }
}
function schedule() {
  clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden) refresh(); }, 2000);
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });

// ---- actions ----------------------------------------------------------------------------

function stripStatus(r) {
  return { id: r.id, name: r.name, enabled: r.enabled, listen: r.listen, domains: r.domains, targets: r.targets, proxy_protocol: r.proxy_protocol };
}

async function toggle(r) {
  try {
    await api('PUT', '/routes/' + encodeURIComponent(r.id), { ...stripStatus(r), enabled: !r.enabled });
  } catch (e) {
    alert('Could not change route: ' + [e.message, ...e.details].join('\n'));
  }
  refresh();
}

async function remove(r) {
  if (!confirm(`Delete route "${r.name}"?\nExisting connections finish; new ones are refused.`)) return;
  try {
    await api('DELETE', '/routes/' + encodeURIComponent(r.id));
  } catch (e) {
    alert('Could not delete: ' + e.message);
  }
  refresh();
}

// ---- editor -----------------------------------------------------------------------------

let editingId = null;

function parseTargets(text) {
  const targets = [], errors = [];
  for (const tok of text.split(/[\s,]+/).filter(Boolean)) {
    const m = tok.match(/^\[([0-9a-fA-F:.]+)\]:(\d{1,5})$/) || tok.match(/^([0-9.]+):(\d{1,5})$/);
    if (!m) { errors.push(`Target "${tok}" must look like 10.0.0.5:8080 or [::1]:8080`); continue; }
    const port = Number(m[2]);
    if (port < 1 || port > 65535) { errors.push(`Target "${tok}": port out of range`); continue; }
    targets.push({ address: m[1], port });
  }
  return { targets, errors };
}

function showEditorErrors(list) {
  const ul = $('#editor-errors');
  ul.replaceChildren(...list.map((m) => h('li', null, m)));
  ul.hidden = list.length === 0;
}

function openEditor(r) {
  editingId = r ? r.id : null;
  $('#editor-title').textContent = r ? 'Edit route' : 'Add route';
  $('#f-name').value = r ? r.name : '';
  $('#f-ip').value = r ? r.listen.ip : '0.0.0.0';
  $('#f-port').value = r ? r.listen.port : '';
  $('#f-domains').value = r ? r.domains.join('\n') : '';
  $('#f-targets').value = r ? r.targets.map((t) => addr(t.address, t.port)).join('\n') : '';
  $('#f-proxy').checked = r ? r.proxy_protocol : false;
  $('#f-enabled').checked = r ? r.enabled : true;
  showEditorErrors([]);
  $('#editor').showModal();
  $('#f-name').focus();
}

$('#editor-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const errs = [];
  const name = $('#f-name').value.trim();
  const port = Number($('#f-port').value.trim());
  if (!name) errs.push('Name is required');
  if (!Number.isInteger(port) || port < 1 || port > 65535) errs.push('Port must be 1-65535');
  const { targets, errors } = parseTargets($('#f-targets').value);
  errs.push(...errors);
  if (!targets.length && !errors.length) errs.push('Add at least one target');
  if (errs.length) return showEditorErrors(errs);

  const body = {
    name,
    enabled: $('#f-enabled').checked,
    listen: { ip: $('#f-ip').value.trim() || '0.0.0.0', port },
    domains: $('#f-domains').value.split(/[\s,]+/).filter(Boolean),
    targets,
    proxy_protocol: $('#f-proxy').checked,
  };
  $('#editor-save').disabled = true;
  try {
    if (editingId) await api('PUT', '/routes/' + encodeURIComponent(editingId), body);
    else await api('POST', '/routes', body);
    $('#editor').close();
    refresh();
  } catch (e) {
    if (e.status !== 401) showEditorErrors(e.details.length ? e.details : [e.message]);
  } finally {
    $('#editor-save').disabled = false;
  }
});
$('#editor-cancel').addEventListener('click', () => $('#editor').close());
$('#btn-add').addEventListener('click', () => openEditor(null));

// ---- login ------------------------------------------------------------------------------

function showLogin(wasRejected) {
  $('#login-error').hidden = !wasRejected;
  if (!$('#login').open) $('#login').showModal();
  $('#f-token').focus();
}
$('#login-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  token = $('#f-token').value.trim();
  try { sessionStorage.setItem(TOKEN_KEY, token); } catch (_) { /* ignore */ }
  $('#f-token').value = '';
  $('#login').close();
  refresh();
});

// ---- import / export --------------------------------------------------------------------

$('#btn-export').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(current.map(stripStatus), null, 2) + '\n'], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: 'edge-lb-routes.json' });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

$('#btn-import').addEventListener('click', () => $('#file').click());
$('#file').addEventListener('change', async (ev) => {
  const file = ev.target.files[0];
  ev.target.value = '';
  if (!file) return;
  try {
    const parsed = JSON.parse(await file.text());
    const routes = Array.isArray(parsed) ? parsed : parsed.routes;
    if (!Array.isArray(routes)) throw new Error('Expected a JSON array of routes');
    if (!confirm(`Replace ALL current routes with the ${routes.length} route(s) in "${file.name}"?`)) return;
    await api('PUT', '/routes', routes);
  } catch (e) {
    alert('Import failed:\n' + [e.message, ...(e.details || [])].join('\n'));
  }
  refresh();
});

// ---- go ---------------------------------------------------------------------------------

if (!token) showLogin(false);
refresh();
schedule();

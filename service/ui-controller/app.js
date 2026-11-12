'use strict';

// No framework and no build step. All data goes in through textContent / text nodes, never
// innerHTML, so names and error strings from the network can't inject markup.

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

// ---- API ---------------------------------------------------------------------------------

class ApiError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details || [];
  }
  /** Everything worth showing the user. */
  get lines() { return this.details.length ? this.details : [this.message]; }
}

async function api(method, path, body) {
  const headers = { 'X-EdgeLB': '1' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch('/api' + path, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (res.status === 401 && path !== '/login' && path !== '/setup') {
    showAuth('login');
    throw new ApiError(401, 'Not signed in');
  }
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || res.statusText, data && data.details);
  return data;
}

// ---- state -------------------------------------------------------------------------------

const S = { status: null, settings: null, tab: 'edges', expanded: new Set(), user: null };

// ---- formatting --------------------------------------------------------------------------

function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 5) return 'just now';
  if (s < 90) return s + 's ago';
  if (s < 5400) return Math.round(s / 60) + 'm ago';
  if (s < 129600) return Math.round(s / 3600) + 'h ago';
  return Math.round(s / 86400) + 'd ago';
}
function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(n >= 100 ? 0 : 1)) + ' ' + u[i];
}
const addr = (ip, port) => (ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`);
const clock = (ts) => new Date(ts * 1000).toLocaleString();

const STATUS = {
  creating: { label: 'Creating server', cls: 'warn', step: 0 },
  waiting_for_ssh: { label: 'Waiting for SSH', cls: 'warn', step: 1 },
  bootstrapping: { label: 'Installing', cls: 'warn', step: 2 },
  joining: { label: 'Joining', cls: 'warn', step: 3 },
  healthy: { label: 'Healthy', cls: 'ok', step: 5 },
  unreachable: { label: 'Unreachable', cls: 'bad', step: 5 },
  draining: { label: 'Draining', cls: 'warn', step: 5 },
  deleting: { label: 'Deleting', cls: 'warn', step: -1 },
  failed: { label: 'Failed', cls: 'bad', step: -1 },
};
const STEPS = ['Server', 'SSH', 'Install', 'Join', 'Serving'];

// ---- dialogs -----------------------------------------------------------------------------

/** Brief confirmation that survives page re-renders. */
function toast(msg) {
  const t = h('div', { class: 'toast', role: 'status' }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 2600);
}

function showErrors(ul, lines) {
  ul.replaceChildren(...lines.map((m) => h('li', null, m)));
  ul.hidden = lines.length === 0;
}

function openDialog(sel) {
  const d = $(sel);
  if (!d.open) d.showModal();
  return d;
}

/** Generic confirmation. opts: title, body, typeName, forceLabel, okLabel, run(force) -> Promise */
function confirmDialog(opts) {
  $('#confirm-title').textContent = opts.title;
  $('#confirm-body').textContent = opts.body;
  $('#confirm-ok').textContent = opts.okLabel || 'Delete';
  const typeWrap = $('#confirm-type-wrap'), forceWrap = $('#confirm-force-wrap');
  typeWrap.hidden = !opts.typeName;
  $('#confirm-type').value = '';
  $('#confirm-type-label').textContent = opts.typeName ? `Type "${opts.typeName}" to confirm` : '';
  forceWrap.hidden = !opts.forceLabel;
  $('#confirm-force').checked = false;
  $('#confirm-force-label').textContent = opts.forceLabel || '';
  showErrors($('#confirm-errors'), []);
  confirmDialog.opts = opts;
  openDialog('#confirm');
}

$('#confirm-cancel').addEventListener('click', () => $('#confirm').close());
$('#confirm-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const o = confirmDialog.opts;
  if (o.typeName && $('#confirm-type').value.trim() !== o.typeName) return showErrors($('#confirm-errors'), [`Type "${o.typeName}" exactly to confirm.`]);
  if (o.forceLabel && !$('#confirm-force').checked) return showErrors($('#confirm-errors'), ['Tick the box to acknowledge.']);
  $('#confirm-ok').disabled = true;
  try {
    await o.run($('#confirm-force').checked);
    $('#confirm').close();
    refresh();
  } catch (e) {
    if (e.status !== 401) showErrors($('#confirm-errors'), e.lines);
  } finally {
    $('#confirm-ok').disabled = false;
  }
});

// ---- auth --------------------------------------------------------------------------------

let authMode = 'login';

function showAuth(mode) {
  authMode = mode;
  const setup = mode === 'setup';
  $('#auth-title').textContent = setup ? 'Welcome to edge-lb' : 'Sign in';
  $('#auth-hint').textContent = setup ? 'Create the administrator account. You will need the setup code the controller printed when it started.' : '';
  $('#f-code-wrap').hidden = !setup;
  $('#f-pass-hint').hidden = !setup;
  $('#f-pass').autocomplete = setup ? 'new-password' : 'current-password';
  $('#auth-submit').textContent = setup ? 'Create account' : 'Sign in';
  showErrors($('#auth-errors'), []);
  $('#top').hidden = true;
  if (!$('#auth').open) $('#auth').showModal();
  (setup ? $('#f-code') : $('#f-user')).focus();
}

$('#auth-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = { username: $('#f-user').value.trim(), password: $('#f-pass').value };
  if (authMode === 'setup') body.setup_code = $('#f-code').value.trim();
  $('#auth-submit').disabled = true;
  try {
    const r = await api('POST', authMode === 'setup' ? '/setup' : '/login', body);
    $('#f-pass').value = '';
    $('#auth').close();
    S.user = r.username;
    startApp();
  } catch (e) {
    showErrors($('#auth-errors'), e.lines);
  } finally {
    $('#auth-submit').disabled = false;
  }
});

$('#btn-signout').addEventListener('click', async () => {
  try { await api('POST', '/logout'); } catch (_) { /* already signed out */ }
  S.status = null;
  showAuth('login');
});

// ---- chrome ------------------------------------------------------------------------------

function renderPills() {
  const st = S.status;
  if (!st) return;
  const healthy = st.edges.filter((e) => e.status === 'healthy').length;
  const pills = [
    h('span', { class: 'pill' }, h('b', null, `${healthy}/${st.edges.length}`), ' edges healthy'),
    h('span', { class: 'pill' }, h('b', null, st.routes.length), ' routes'),
  ];
  if (st.dns_names) {
    const d = st.dns;
    const bad = d.last_error, held = d.held;
    pills.push(h('span', { class: 'pill' + (bad ? ' bad' : held ? ' warn' : '') }, 'DNS ',
      h('b', null, bad ? 'error' : held ? 'held' : d.last_sync ? 'synced' : 'pending')));
  }
  pills.push(h('span', { class: 'pill' }, 'v', st.version));
  $('#pills').replaceChildren(...pills);
  $('#whoami').textContent = S.user || '';
}

function setTab(tab) {
  S.tab = ['edges', 'routes', 'settings', 'activity'].includes(tab) ? tab : 'edges';
  document.querySelectorAll('#tabs a').forEach((a) => a.classList.toggle('active', a.dataset.tab === S.tab));
  renderPage(true);
}
window.addEventListener('hashchange', () => setTab(location.hash.replace('#/', '')));

function renderPage(full) {
  const main = $('#main');
  if (S.tab === 'edges') return renderEdges(main);
  if (S.tab === 'routes') return renderRoutes(main);
  if (!full) return; // settings & activity are not live: don't clobber what the user is typing
  if (S.tab === 'settings') return renderSettings(main);
  if (S.tab === 'activity') return renderActivity(main);
}

// ---- edges page --------------------------------------------------------------------------

function providerText(e) {
  return e.provider.kind === 'hetzner' ? `Hetzner · ${e.provider.location} · ${e.provider.server_type}` : 'Existing machine';
}

function stepBar(e) {
  const info = STATUS[e.status];
  if (info.step < 0) return null;
  return h('div', { class: 'steps', title: STEPS.join(' → ') },
    STEPS.map((name, i) => h('i', { class: i < info.step ? 'done' : i === info.step ? 'now' : '', title: name })));
}

function edgeCard(e) {
  const info = STATUS[e.status] || { label: e.status, cls: '' };
  const live = e.live, ls = live && live.status;
  const open = S.expanded.has(e.id);
  const dotCls = e.status === 'healthy' ? 'ok' : info.cls;
  const healthyCount = S.status.edges.filter((x) => x.status === 'healthy').length;

  return h('div', { class: 'card edge', 'data-id': e.id },
    h('div', { class: 'cell' },
      h('div', { class: 'name' }, h('span', { class: 'dot ' + dotCls }), e.name),
      h('div', { class: 'chips' }, e.region && h('span', { class: 'chip' }, e.region), e.id !== e.region && h('span', { class: 'chip mono' }, e.id)),
    ),
    h('div', { class: 'cell' },
      h('span', { class: 'label' }, 'Machine'),
      h('div', { class: 'mono' }, e.ip ? addr(e.ip, e.mgmt_port).replace(/:\d+$/, '') : 'pending…'),
      h('div', { class: 'sub' }, providerText(e)),
      live && live.version && h('div', { class: 'sub' }, 'edge v' + live.version),
    ),
    h('div', { class: 'cell' },
      h('span', { class: 'label' }, 'Status'),
      h('span', { class: 'badge ' + info.cls }, info.label),
      stepBar(e),
      e.error && h('div', { class: 'err' }, e.error),
      live && live.last_seen && e.status !== 'creating' && h('div', { class: 'sub' }, 'seen ' + ago(live.last_seen)),
    ),
    h('div', { class: 'cell' },
      h('span', { class: 'label' }, 'Traffic'),
      ls ? [
        h('div', null, `${ls.active_connections} active connection${ls.active_connections === 1 ? '' : 's'}`),
        h('div', { class: 'sub' }, `${ls.listeners} listener${ls.listeners === 1 ? '' : 's'} · ${ls.routes.length} route${ls.routes.length === 1 ? '' : 's'}`),
      ] : h('div', { class: 'sub' }, '—'),
    ),
    h('div', { class: 'row-actions' },
      e.status === 'failed' && h('button', { class: 'small', type: 'button', onclick: () => retryEdge(e) }, 'Retry'),
      h('button', { class: 'small', type: 'button', onclick: () => { S.expanded.has(e.id) ? S.expanded.delete(e.id) : S.expanded.add(e.id); renderPage(true); } }, open ? 'Hide log' : 'Log'),
      (e.status === 'failed' || e.status === 'deleting') && h('button', { class: 'small', type: 'button', title: 'Drop this record without touching the provider or machine', onclick: () => forgetEdge(e) }, 'Forget'),
      e.status !== 'deleting' && e.status !== 'draining' && h('button', { class: 'small danger', type: 'button', onclick: () => deleteEdge(e, healthyCount) }, 'Delete'),
    ),
    open && h('div', { class: 'log mono' }, [...e.log].reverse().map((l) => h('div', null, h('time', null, new Date(l.ts * 1000).toLocaleTimeString()), h('span', null, l.msg)))),
  );
}

function renderEdges(main) {
  const edges = S.status ? S.status.edges : [];
  main.replaceChildren(
    h('div', { class: 'page-head' }, h('h2', null, 'Edges'), h('button', { class: 'primary', type: 'button', onclick: openEdgeDialog }, 'Add edge')),
    edges.length
      ? h('div', { class: 'list' }, edges.map(edgeCard))
      : h('div', { class: 'empty' }, 'No edges yet. An edge is a public machine that accepts traffic and forwards it to your targets.',
        h('div', null, h('button', { class: 'primary', type: 'button', onclick: openEdgeDialog }, 'Add your first edge'))),
  );
}

function deleteEdge(e, healthyCount) {
  const lastHealthy = e.status === 'healthy' && healthyCount === 1;
  confirmDialog({
    title: `Delete ${e.name}?`,
    body: e.provider.kind === 'hetzner'
      ? 'The server is removed from DNS, given time to finish its connections, then destroyed at Hetzner (billing stops).'
      : 'The edge is removed from DNS and edge-lb is uninstalled from the machine. The machine itself is not touched.',
    typeName: e.name,
    forceLabel: lastHealthy ? 'This is the only healthy edge. Deleting it takes your service offline.' : null,
    run: (force) => api('DELETE', `/edges/${encodeURIComponent(e.id)}${force ? '?force=true' : ''}`),
  });
}

function forgetEdge(e) {
  confirmDialog({
    title: `Forget ${e.name}?`,
    body: 'Removes the record only. The provider server and the machine are NOT touched, so a billed server may keep running. Only use this if you have already removed it yourself.',
    okLabel: 'Forget',
    run: () => api('POST', `/edges/${encodeURIComponent(e.id)}/forget`),
  });
}

async function retryEdge(e) {
  try { await api('POST', `/edges/${encodeURIComponent(e.id)}/retry`); } catch (err) { alert(err.lines.join('\n')); }
  refresh();
}

// ---- add-edge dialog ---------------------------------------------------------------------

let catalog = null;

function kind() { return document.querySelector('#edge-kind input:checked').value; }

function updateKind() {
  const k = kind();
  $('#e-hetzner').hidden = k !== 'hetzner';
  $('#e-manual').hidden = k !== 'manual';
  updateSave();
}

function updateSave() {
  const noToken = kind() === 'hetzner' && S.settings && !S.settings.hetzner_token_set;
  $('#e-notoken').hidden = !noToken;
  $('#edge-save').disabled = noToken || (kind() === 'hetzner' && !catalog);
}

function fillCatalog() {
  const loc = $('#e-location'), typ = $('#e-type');
  const keepLoc = loc.value, keepTyp = typ.value;
  loc.replaceChildren(...catalog.locations.map((l) => h('option', { value: l.name }, `${l.city}, ${l.country} — ${l.name} (${l.network_zone})`)));
  const usable = catalog.server_types.filter((t) => t.compatible);
  typ.replaceChildren(...usable.map((t) => h('option', { value: t.name }, `${t.name} · ${t.cores} vCPU · ${t.memory_gb} GB RAM · ${t.disk_gb} GB disk`)));
  if (keepLoc) loc.value = keepLoc;
  if (keepTyp) typ.value = keepTyp;
  updateCost();
}

function updateCost() {
  const t = catalog && catalog.server_types.find((x) => x.name === $('#e-type').value);
  const p = t && t.prices.find((x) => x.location === $('#e-location').value);
  $('#e-cost').replaceChildren(...(p ? ['About ', h('b', null, `€${p.monthly.toFixed(2)}/month`), ' (gross, billed by Hetzner while the edge exists).'] : t ? ['This type isn’t offered at this location.'] : []));
  const loc = catalog && catalog.locations.find((l) => l.name === $('#e-location').value);
  if (loc && !$('#e-region').dataset.touched) $('#e-region').value = loc.network_zone;
}

async function openEdgeDialog() {
  showErrors($('#edge-errors'), []);
  $('#edge-form').reset();
  delete $('#e-region').dataset.touched;
  catalog = null;
  openDialog('#edge-dialog');
  updateKind();
  try {
    S.settings = await api('GET', '/settings');
    updateSave();
    const key = await api('GET', '/ssh-key');
    $('#e-key').textContent = `echo '${key.public_key}' >> ~/.ssh/authorized_keys`;
    if (S.settings.hetzner_token_set) {
      catalog = await api('GET', '/catalog');
      fillCatalog();
    }
  } catch (e) {
    if (e.status !== 401) showErrors($('#edge-errors'), e.lines);
  }
  updateSave();
}

document.querySelectorAll('#edge-kind input').forEach((r) => r.addEventListener('change', updateKind));
$('#e-location').addEventListener('change', updateCost);
$('#e-type').addEventListener('change', updateCost);
$('#e-region').addEventListener('input', () => { $('#e-region').dataset.touched = '1'; });
$('#e-goto-settings').addEventListener('click', () => $('#edge-dialog').close());
$('#edge-cancel').addEventListener('click', () => $('#edge-dialog').close());
$('#e-copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#e-key').textContent); $('#e-copy').textContent = 'Copied'; } catch (_) { /* clipboard blocked */ }
});

$('#edge-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = { name: $('#e-name').value.trim(), region: $('#e-region').value.trim() };
  if (kind() === 'hetzner') {
    body.provider = { kind: 'hetzner', location: $('#e-location').value, server_type: $('#e-type').value };
  } else {
    body.provider = { kind: 'manual' };
    body.ip = $('#e-ip').value.trim();
    body.ssh_user = $('#e-sshuser').value.trim() || 'root';
    body.ssh_port = Number($('#e-sshport').value) || 22;
  }
  if (!body.name) return showErrors($('#edge-errors'), ['Give the edge a name.']);
  $('#edge-save').disabled = true;
  try {
    await api('POST', '/edges', body);
    $('#edge-dialog').close();
    location.hash = '#/edges';
    refresh();
  } catch (e) {
    if (e.status !== 401) showErrors($('#edge-errors'), e.lines);
  } finally {
    updateSave();
  }
});

// ---- routes page -------------------------------------------------------------------------

function applicableEdges(r) {
  const all = S.status.edges.filter((e) => e.status !== 'deleting');
  return r.edges.length ? all.filter((e) => r.edges.includes(e.id)) : all;
}

function routeOnEdge(r, e) {
  const rs = e.live && e.live.status && e.live.status.routes.find((x) => x.id === r.id);
  let cls = '', tip = 'Not applied yet';
  if (!r.enabled) { tip = 'Route disabled'; }
  else if (e.status !== 'healthy') { tip = `Edge is ${e.status.replace('_', ' ')}`; cls = e.status === 'unreachable' || e.status === 'failed' ? 'bad' : ''; }
  else if (rs) {
    if (rs.status.state === 'listening') { cls = rs.status.targets.length && rs.status.targets.every((t) => t.healthy === false) ? 'bad' : rs.status.targets.some((t) => t.healthy === false) ? 'warn' : 'ok'; tip = cls === 'ok' ? 'Listening' : 'Listening; some targets are down'; }
    else if (rs.status.state === 'error') { cls = 'bad'; tip = 'Cannot listen: ' + (rs.status.error || ''); }
  } else { cls = 'warn'; }
  const conns = rs && rs.status ? rs.status.active_connections : null;
  return h('div', { class: 'target', title: tip }, h('span', { class: 'dot ' + cls }), h('span', null, e.name), conns != null && h('span', { class: 'sub' }, `${conns} active`));
}

function routeCard(c) {
  const edges = applicableEdges(c);
  const domains = c.domains.length ? c.domains.map((d) => h('span', { class: 'chip mono' }, d)) : [h('span', { class: 'chip any' }, 'everything on this port')];
  return h('div', { class: 'card route' + (c.enabled ? '' : ' dim'), 'data-id': c.id },
    h('div', { class: 'cell' }, h('div', { class: 'name' }, c.name), h('div', { class: 'sub mono' }, c.id)),
    h('div', { class: 'cell' }, h('span', { class: 'label' }, 'Domains'), h('div', { class: 'chips' }, domains)),
    h('div', { class: 'cell' }, h('span', { class: 'label' }, 'Listen'), h('div', { class: 'mono' }, addr(c.listen.ip, c.listen.port)),
      c.proxy_protocol && h('div', { class: 'chips' }, h('span', { class: 'chip flag' }, 'PROXY v2'))),
    h('div', { class: 'cell' }, h('span', { class: 'label' }, 'Targets'),
      h('div', { class: 'targets' }, c.targets.map((t) => h('div', { class: 'target mono' }, addr(t.address, t.port))))),
    h('div', { class: 'cell' }, h('span', { class: 'label' }, c.edges.length ? 'Runs on' : 'Runs on (all edges)'),
      h('div', { class: 'targets' }, edges.length ? edges.map((e) => routeOnEdge(c, e)) : h('span', { class: 'sub' }, 'no edges'))),
    h('div', { class: 'row-actions' },
      h('button', { class: 'small', type: 'button', onclick: () => toggleRoute(c) }, c.enabled ? 'Disable' : 'Enable'),
      h('button', { class: 'small', type: 'button', onclick: () => openRouteDialog(c) }, 'Edit'),
      h('button', { class: 'small danger', type: 'button', onclick: () => deleteRoute(c) }, 'Delete')),
  );
}

function renderRoutes(main) {
  const routes = S.status ? S.status.routes : [];
  const sorted = [...routes].sort((a, b) => a.listen.port - b.listen.port || a.name.localeCompare(b.name));
  main.replaceChildren(
    h('div', { class: 'page-head' }, h('h2', null, 'Routes'), h('button', { class: 'primary', type: 'button', onclick: () => openRouteDialog(null) }, 'Add route')),
    sorted.length
      ? h('div', { class: 'list' }, sorted.map(routeCard))
      : h('div', { class: 'empty' }, 'No routes yet. A route sends traffic arriving on a port (optionally for certain domains) to one or more targets, on all your edges or just some.',
        h('div', null, h('button', { class: 'primary', type: 'button', onclick: () => openRouteDialog(null) }, 'Add a route'))),
  );
}

const routeBody = (c) => ({ id: c.id, name: c.name, enabled: c.enabled, listen: c.listen, domains: c.domains, targets: c.targets, proxy_protocol: c.proxy_protocol, edges: c.edges });

async function toggleRoute(c) {
  try { await api('PUT', '/routes/' + encodeURIComponent(c.id), { ...routeBody(c), enabled: !c.enabled }); } catch (e) { alert(e.lines.join('\n')); }
  refresh();
}

function deleteRoute(c) {
  confirmDialog({
    title: `Delete route ${c.name}?`,
    body: 'It is removed from every edge. Existing connections finish; new ones are refused.',
    run: () => api('DELETE', '/routes/' + encodeURIComponent(c.id)),
  });
}

// ---- route editor ------------------------------------------------------------------------

let editingRoute = null;

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

function scopeMode() { return document.querySelector('input[name=scope]:checked').value; }

function updateScope() {
  $('#r-edges').hidden = scopeMode() !== 'some';
}

function openRouteDialog(c) {
  editingRoute = c;
  $('#route-title').textContent = c ? 'Edit route' : 'Add route';
  $('#r-name').value = c ? c.name : '';
  $('#r-ip').value = c ? c.listen.ip : '0.0.0.0';
  $('#r-port').value = c ? c.listen.port : '';
  $('#r-domains').value = c ? c.domains.join('\n') : '';
  $('#r-targets').value = c ? c.targets.map((t) => addr(t.address, t.port)).join('\n') : '';
  $('#r-proxy').checked = c ? c.proxy_protocol : false;
  $('#r-enabled').checked = c ? c.enabled : true;
  const scoped = c && c.edges.length > 0;
  document.querySelector(`input[name=scope][value=${scoped ? 'some' : 'all'}]`).checked = true;
  const edges = S.status.edges.filter((e) => e.status !== 'deleting');
  $('#r-edges').replaceChildren(...(edges.length
    ? edges.map((e) => h('label', { class: 'check' }, h('input', { type: 'checkbox', value: e.id, checked: scoped && c.edges.includes(e.id) }), e.name, e.region && h('small', null, e.region)))
    : [h('span', { class: 'sub' }, 'No edges yet.')]));
  updateScope();
  showErrors($('#route-errors'), []);
  openDialog('#route-dialog');
  $('#r-name').focus();
}

document.querySelectorAll('input[name=scope]').forEach((r) => r.addEventListener('change', updateScope));
$('#route-cancel').addEventListener('click', () => $('#route-dialog').close());

$('#route-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const errs = [];
  const name = $('#r-name').value.trim();
  const port = Number($('#r-port').value.trim());
  if (!name) errs.push('Name is required');
  if (!Number.isInteger(port) || port < 1 || port > 65535) errs.push('Port must be 1-65535');
  const { targets, errors } = parseTargets($('#r-targets').value);
  errs.push(...errors);
  if (!targets.length && !errors.length) errs.push('Add at least one target');
  const edges = scopeMode() === 'some' ? [...document.querySelectorAll('#r-edges input:checked')].map((i) => i.value) : [];
  if (scopeMode() === 'some' && !edges.length) errs.push('Pick at least one edge, or choose "All edges"');
  if (errs.length) return showErrors($('#route-errors'), errs);

  const body = {
    name, enabled: $('#r-enabled').checked, edges,
    listen: { ip: $('#r-ip').value.trim() || '0.0.0.0', port },
    domains: $('#r-domains').value.split(/[\s,]+/).filter(Boolean),
    targets, proxy_protocol: $('#r-proxy').checked,
  };
  $('#route-save').disabled = true;
  try {
    if (editingRoute) await api('PUT', '/routes/' + encodeURIComponent(editingRoute.id), body);
    else await api('POST', '/routes', body);
    $('#route-dialog').close();
    refresh();
  } catch (e) {
    if (e.status !== 401) showErrors($('#route-errors'), e.lines);
  } finally {
    $('#route-save').disabled = false;
  }
});

// ---- settings page -----------------------------------------------------------------------

function sectionForm(title, intro, fields, actions) {
  return h('form', { class: 'panel', onsubmit: (ev) => ev.preventDefault() }, h('h3', null, title), intro && h('p', { class: 'hint' }, intro), fields, actions);
}

function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', null, label), input, hint && h('small', null, hint));
}

async function saveSection(btn, errs, body) {
  btn.disabled = true;
  showErrors(errs, []);
  try {
    S.settings = await api('PUT', '/settings', body);
    toast('Saved');
    renderPage(true);
  } catch (e) {
    if (e.status !== 401) showErrors(errs, e.lines);
  } finally {
    btn.disabled = false;
  }
}

async function renderSettings(main) {
  try { S.settings = await api('GET', '/settings'); } catch (_) { return; }
  const st = S.settings;

  // Hetzner
  const hzTok = h('input', { type: 'password', autocomplete: 'off', placeholder: st.hetzner_token_set ? '•••••••• (set; leave blank to keep)' : 'Hetzner Cloud API token (read & write)' });
  const hzImg = h('input', { value: st.hetzner_image });
  const hzErr = h('ul', { class: 'errors', hidden: true });
  const hzSave = h('button', { class: 'primary', type: 'button' }, 'Save');
  hzSave.addEventListener('click', () => saveSection(hzSave, hzErr, { hetzner_token: hzTok.value.trim() || undefined, hetzner_image: hzImg.value.trim() }));
  const hzClear = st.hetzner_token_set && h('button', { class: 'danger', type: 'button', onclick: () => saveSection(hzSave, hzErr, { hetzner_token: '' }) }, 'Remove token');

  // Limits
  const maxE = h('input', { value: st.max_edges, inputmode: 'numeric' });
  const drain = h('input', { value: st.drain_seconds, inputmode: 'numeric' });
  const limErr = h('ul', { class: 'errors', hidden: true });
  const limSave = h('button', { class: 'primary', type: 'button' }, 'Save');
  limSave.addEventListener('click', () => saveSection(limSave, limErr, { max_edges: Number(maxE.value), drain_seconds: Number(drain.value) }));

  // DNS
  const d = st.dns;
  const cfTok = h('input', { type: 'password', autocomplete: 'off', placeholder: d && d.token_set ? '•••••••• (set; leave blank to keep)' : 'Cloudflare API token (Zone · DNS · Edit)' });
  const zone = h('input', { value: d ? d.zone_id : '', spellcheck: 'false' });
  const names = h('textarea', { rows: 3, spellcheck: 'false', placeholder: 'app.example.com' }, d ? d.names.join('\n') : '');
  const ttl = h('input', { value: d ? d.ttl : 300, inputmode: 'numeric' });
  const dnsErr = h('ul', { class: 'errors', hidden: true });
  const dnsSave = h('button', { class: 'primary', type: 'button' }, 'Save');
  dnsSave.addEventListener('click', () => saveSection(dnsSave, dnsErr, {
    dns: { cloudflare_token: cfTok.value.trim() || undefined, zone_id: zone.value.trim(), names: names.value.split(/[\s,]+/).filter(Boolean), ttl: Number(ttl.value) },
  }));
  const dnsOff = d && h('button', { class: 'danger', type: 'button', onclick: () => saveSection(dnsSave, dnsErr, { clear_dns: true }) }, 'Turn off');

  // SSH key
  let key = '';
  try { key = (await api('GET', '/ssh-key')).public_key; } catch (_) { /* shown empty */ }
  const keyPre = h('pre', { class: 'code' }, key);

  main.replaceChildren(
    h('div', { class: 'page-head' }, h('h2', null, 'Settings')),
    sectionForm('Hetzner Cloud', 'Lets the controller create and destroy servers. The token is stored on the controller and never shown again.',
      [field('API token', hzTok), field('Server image', hzImg, 'Operating system image for new servers. Needs systemd and apt or dnf.'), hzErr],
      h('div', { class: 'buttons' }, hzSave, hzClear)),
    sectionForm('Limits', 'Every edge is a billed server. These guard against runaway costs and abrupt deletions.',
      [field('Maximum edges', maxE), field('Drain time (seconds)', drain, 'How long a deleted edge keeps serving existing connections. Set this at least as long as your DNS TTL.'), limErr],
      h('div', { class: 'buttons' }, limSave)),
    sectionForm('DNS (Cloudflare)', 'Names listed here are pointed at every healthy edge, and unhealthy edges are removed. Only records created by edge-lb are ever changed. Records are DNS-only (never proxied), which TLS passthrough needs.',
      [field('API token', cfTok), field('Zone ID', zone), field('Names', names, 'One fully-qualified name per line.'), field('TTL (seconds)', ttl, '1 = automatic, otherwise 60–86400.'), dnsErr],
      h('div', { class: 'buttons' }, dnsSave, dnsOff)),
    sectionForm('Controller SSH key', 'To adopt an existing machine, add this public key to its authorized_keys. New Hetzner servers get it automatically.',
      [keyPre], null),
    h('div', { class: 'panel' }, h('h3', null, 'Account'),
      h('div', { class: 'buttons' }, h('button', { type: 'button', onclick: () => { $('#password-form').reset(); showErrors($('#password-errors'), []); openDialog('#password-dialog'); } }, 'Change password'))),
  );
}

$('#password-cancel').addEventListener('click', () => $('#password-dialog').close());
$('#password-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    await api('POST', '/password', { current: $('#p-cur').value, new: $('#p-new').value });
    $('#password-dialog').close();
  } catch (e) {
    if (e.status !== 401) showErrors($('#password-errors'), e.lines);
  }
});

// ---- activity page -----------------------------------------------------------------------

async function renderActivity(main) {
  let rows = [];
  try { rows = await api('GET', '/audit'); } catch (_) { return; }
  main.replaceChildren(
    h('div', { class: 'page-head' }, h('h2', null, 'Activity'), h('button', { class: 'ghost', type: 'button', onclick: () => renderPage(true) }, 'Refresh')),
    rows.length
      ? h('table', { class: 'audit' }, h('thead', null, h('tr', null, ['When', 'Who', 'What', 'Detail'].map((t) => h('th', null, t)))),
        h('tbody', null, rows.map((r) => h('tr', null, h('td', { title: clock(r.ts) }, ago(r.ts)), h('td', null, r.actor), h('td', { class: 'mono' }, r.action), h('td', { class: 'detail' }, r.detail)))))
      : h('div', { class: 'empty' }, 'Nothing has happened yet.'),
  );
}

// ---- polling & boot ----------------------------------------------------------------------

async function refresh() {
  try {
    S.status = await api('GET', '/status');
    $('#conn').className = 'dot ok';
    $('#conn').title = 'Connected';
    renderPills();
    renderPage(false);
  } catch (e) {
    $('#conn').className = 'dot bad';
    $('#conn').title = e.status === 401 ? 'Signed out' : 'Cannot reach the controller';
  }
}

let timer = null;
async function startApp() {
  $('#top').hidden = false;
  await refresh();
  setTab(location.hash.replace('#/', '') || 'edges');
  clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden && !document.querySelector('dialog[open]')) refresh(); }, 2000);
}
document.addEventListener('visibilitychange', () => { if (!document.hidden && S.status) refresh(); });

(async function boot() {
  try {
    const s = await (await fetch('/api/session', { credentials: 'same-origin' })).json();
    if (s.setup_needed) return showAuth('setup');
    if (!s.authenticated) return showAuth('login');
    S.user = s.username;
    startApp();
  } catch (_) {
    $('#main').replaceChildren(h('div', { class: 'empty' }, 'Cannot reach the controller.'));
  }
})();

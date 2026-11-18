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
/** "12m" until a timestamp in the future. */
function inFuture(ts) {
  const s = Math.max(0, Math.round(ts - Date.now() / 1000));
  if (s < 90) return s + 's';
  if (s < 5400) return Math.round(s / 60) + 'm';
  return Math.round(s / 3600) + 'h';
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
  if (st.sites && st.sites.length) {
    const online = st.sites.filter((x) => x.gateway.online).length;
    pills.push(h('span', { class: 'pill' + (online < st.sites.length ? ' warn' : '') }, h('b', null, `${online}/${st.sites.length}`), ' gateways online'));
  }
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
  S.tab = ['edges', 'sites', 'routes', 'settings', 'activity'].includes(tab) ? tab : 'edges';
  document.querySelectorAll('#tabs a').forEach((a) => a.classList.toggle('active', a.dataset.tab === S.tab));
  renderPage(true);
}
window.addEventListener('hashchange', () => setTab(location.hash.replace('#/', '')));

function renderPage(full) {
  const main = $('#main');
  if (S.tab === 'edges') return renderEdges(main);
  if (S.tab === 'sites') return renderSites(main);
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

/** One line about the edge's WireGuard side, shown once it matters (sites exist or it is set up). */
function tunnelNote(e) {
  const sites = (S.status && S.status.sites) || [];
  const serving = ['healthy', 'unreachable', 'joining', 'draining'].includes(e.status);
  if (e.wg_public_key) return h('div', { class: 'sub', title: 'This edge reaches sites over WireGuard' }, 'tunnel ' + (e.tunnel_ip || '…'));
  if (serving && sites.length) return h('div', { class: 'sub warn-text', title: 'WireGuard was not available when this edge was installed, so it cannot reach sites' }, 'no WireGuard: cannot reach sites');
  return null;
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
      tunnelNote(e),
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

// ---- sites page --------------------------------------------------------------------------

function gatewayState(g) {
  if (!g.enrolled) return g.enrol_pending_until ? { label: 'Waiting for gateway', cls: 'warn' } : { label: 'No gateway yet', cls: '' };
  if (!g.online) return { label: 'Offline', cls: 'bad' };
  if (g.error) return { label: 'Error', cls: 'bad' };
  if (g.in_sync === false) return { label: 'Applying…', cls: 'warn' };
  return { label: 'Online', cls: 'ok' };
}

const siteName = (id) => { const s = ((S.status && S.status.sites) || []).find((x) => x.id === id); return s ? s.name : id; };

function siteCard(site) {
  const g = site.gateway, st = gatewayState(g);
  const tunnels = !g.enrolled
    ? [h('span', { class: 'sub' }, g.enrol_pending_until ? 'shown once the gateway connects' : '—')]
    : g.tunnels.length
    ? g.tunnels.map((t) => h('div', { class: 'target', title: t.up ? 'Tunnel is up' : t.up === false ? 'No recent handshake' : 'Unknown while the gateway is offline' },
      h('span', { class: 'dot ' + (t.up ? 'ok' : t.up === false ? 'bad' : '') }), h('span', null, t.edge_name),
      t.handshake_age_secs != null && h('span', { class: 'sub' }, t.handshake_age_secs + 's')))
    : [h('span', { class: 'sub' }, 'no edges with WireGuard yet')];
  return h('div', { class: 'card site', 'data-id': site.id },
    h('div', { class: 'cell' },
      h('div', { class: 'name' }, site.name),
      h('div', { class: 'chips' }, site.lan_cidrs.map((c) => h('span', { class: 'chip mono' }, c)))),
    h('div', { class: 'cell' },
      h('span', { class: 'label' }, 'Gateway'),
      h('span', { class: 'badge ' + st.cls }, st.label),
      g.error && h('div', { class: 'err' }, g.error),
      g.enrolled && h('div', { class: 'sub' }, g.online ? `v${g.version || '?'} · seen ${ago(g.last_seen)}` : `last seen ${ago(g.last_seen)}`),
      g.enrolled && g.tunnel_ip && h('div', { class: 'sub mono' }, 'tunnel ' + g.tunnel_ip),
      !g.enrolled && g.enrol_pending_until && h('div', { class: 'sub' }, 'command expires in ' + inFuture(g.enrol_pending_until)),
    ),
    h('div', { class: 'cell' }, h('span', { class: 'label' }, 'Tunnels to edges'), h('div', { class: 'targets' }, tunnels)),
    h('div', { class: 'cell' }, h('span', { class: 'label' }, 'Routes'), h('div', null, `${site.routes} route${site.routes === 1 ? '' : 's'}`)),
    h('div', { class: 'row-actions' },
      h('button', { class: 'small' + (g.enrolled ? '' : ' primary'), type: 'button', onclick: () => openEnrol(site) }, g.enrolled ? 'Re-enrol gateway' : 'Connect gateway'),
      h('button', { class: 'small', type: 'button', onclick: () => openSiteDialog(site) }, 'Edit'),
      h('button', { class: 'small danger', type: 'button', onclick: () => deleteSite(site) }, 'Delete')),
  );
}

function renderSites(main) {
  const sites = (S.status && S.status.sites) || [];
  const add = () => openSiteDialog(null);
  const noListener = S.status && !S.status.gateway_listener;
  main.replaceChildren(...[
    h('div', { class: 'page-head' }, h('h2', null, 'Sites & gateways'), h('button', { class: 'primary', type: 'button', onclick: add }, 'Add site')),
    noListener ? h('div', { class: 'callout' },
      h('div', null, h('strong', null, 'Gateways can\'t connect yet. '), 'This controller isn\'t listening for them.'),
      h('button', { class: 'small', type: 'button', onclick: openListenerHelp }, 'Turn on gateways')) : null,
    sites.length
      ? h('div', { class: 'list' }, sites.map(siteCard))
      : h('div', { class: 'empty' }, 'No sites yet. A site is a network behind a gateway, like your home LAN, that your edges can reach over WireGuard without opening any ports at home. Add one and you get a single command to run there; this page shows when it connects.',
        h('div', null, h('button', { class: 'primary', type: 'button', onclick: add }, 'Add your first site'))),
  ].filter(Boolean));
}

let editingSite = null;

function openSiteDialog(site) {
  editingSite = site;
  $('#site-title').textContent = site ? 'Edit site' : 'Add a site';
  $('#site-save').textContent = site ? 'Save' : 'Save and connect a gateway';
  $('#s-name').value = site ? site.name : '';
  $('#s-cidrs').value = site ? site.lan_cidrs.join('\n') : '';
  showErrors($('#site-errors'), []);
  openDialog('#site-dialog');
  $('#s-name').focus();
}

$('#site-cancel').addEventListener('click', () => $('#site-dialog').close());
$('#site-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const name = $('#s-name').value.trim();
  const lan_cidrs = $('#s-cidrs').value.split(/[\s,]+/).filter(Boolean);
  const errs = [];
  if (!name) errs.push('Name is required');
  if (!lan_cidrs.length) errs.push('Add at least one LAN range, such as 192.168.1.0/24');
  if (errs.length) return showErrors($('#site-errors'), errs);
  $('#site-save').disabled = true;
  try {
    if (editingSite) {
      await api('PUT', '/sites/' + encodeURIComponent(editingSite.id), { name, lan_cidrs });
      $('#site-dialog').close();
      refresh();
    } else {
      // A new site goes straight on to its gateway: one flow from "add" to "connected".
      const created = await api('POST', '/sites', { name, lan_cidrs });
      $('#site-dialog').close();
      refresh();
      openEnrol(created);
    }
  } catch (e) {
    if (e.status !== 401) showErrors($('#site-errors'), e.lines);
  } finally {
    $('#site-save').disabled = false;
  }
});

function deleteSite(site) {
  confirmDialog({
    title: `Delete site ${site.name}?`,
    body: 'Edges stop tunnelling to it. A site that routes still use can\'t be deleted. The gateway machine is left as it is: stop its edge-lb-gateway service when you no longer need it.',
    typeName: site.name,
    run: () => api('DELETE', '/sites/' + encodeURIComponent(site.id)),
  });
}

// ---- connecting a gateway ----------------------------------------------------------------
//
// One dialog, three things it can show: how to turn the gateway listener on (when the controller
// isn't listening yet), the one-time command, and a live line that follows the gateway from
// "waiting" to "connected". It polls on its own because the page's refresh is paused while a
// dialog is open.

let enrolSite = null;      // the site being connected, or null when only showing how to enable gateways
let enrolBaseline = null;  // enrolled_at before this command was issued, to tell a *new* gateway from the old one
let enrolTimer = null;
let enrolExpires = 0;

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast('Copied'); } catch (_) { toast('Select the text and copy it'); }
}

/** What to remember about the network once the listener is on, for how this controller is run. */
function listenerNote() {
  const how = S.status && S.status.deployment;
  if (how === 'desktop') return 'The first time it listens, Windows asks whether to let edge-lb through its firewall: allow it for the kind of network this PC is on. This PC has to be on when a gateway is first connected or changed; traffic that already flows keeps flowing without it.';
  if (how === 'server') return 'Also allow this port inbound in the server\'s firewall and your provider\'s, so the gateway machine can reach it.';
  return 'Make sure this TCP port is reachable from the gateway machine.';
}

/**
 * The gateway listener controls, shared by the Settings page and the gateway dialog (when the
 * listener is still off). `gw` is `settings.gateway`; `onSaved` runs after a successful change.
 * Returns the pieces so each place can lay them out in its own frame.
 */
function gatewayControls(gw, onSaved) {
  const locked = gw.locked;
  const listen = h('input', { value: gw.listen || '0.0.0.0:7444', spellcheck: 'false', disabled: locked });
  const host = h('input', { value: gw.host || gw.suggested_host || '', placeholder: 'ctl.example.com or 192.168.1.20', spellcheck: 'false', disabled: locked });
  const errs = h('ul', { class: 'errors', hidden: true });
  const state = gw.active
    ? h('p', { class: 'gw-state' }, h('span', { class: 'dot ok' }), `Listening. Gateways are told to dial ${gw.active}.`)
    : gw.error
      ? h('p', { class: 'err' }, `The saved listener isn't running: ${gw.error}`)
      : h('p', { class: 'hint' }, 'Off: no gateway can connect yet.');
  const fields = [
    state,
    locked && h('p', { class: 'hint' }, 'This is fixed by the controller\'s startup options (the command line, app.toml or the installer), so it can\'t be changed here.'),
    field('Listen on', listen, 'Where this controller waits for gateways. 0.0.0.0 means every network interface. The port has to be free.'),
    field('Gateways dial', host, gw.host
      ? 'The name or IPv4 address (optionally :port) gateways use to reach this controller.'
      : 'Pre-filled with this machine\'s address on its network. Change it if gateways reach it by another name or a public address.'),
    h('p', { class: 'hint' }, listenerNote()),
    errs,
  ].filter(Boolean);
  const save = h('button', { class: 'primary', type: 'button' }, gw.active || gw.listen ? 'Save' : 'Turn on');
  save.addEventListener('click', () => changeGateway(save, errs, { gateway: { listen: listen.value.trim(), host: host.value.trim() } }, gw, onSaved));
  const off = !locked && (gw.active || gw.listen) && h('button', { class: 'danger', type: 'button' }, 'Turn off');
  if (off) {
    off.addEventListener('click', () => {
      const enrolled = ((S.status && S.status.sites) || []).some((s) => s.gateway.enrolled);
      if (!enrolled) return changeGateway(off, errs, { clear_gateway: true }, gw, onSaved);
      confirmDialog({
        title: 'Turn off the gateway listener?',
        body: 'Gateways that are already installed keep their tunnels, but they can no longer check in, so they won\'t hear about new edges or changes until you turn it back on.',
        okLabel: 'Turn off',
        run: async () => { S.settings = await api('PUT', '/settings', { clear_gateway: true }); S.status = await api('GET', '/status'); onSaved(); },
      });
    });
  }
  return { fields, actions: h('div', { class: 'buttons' }, !locked && save, off) };
}

async function changeGateway(btn, errs, body, before, onSaved) {
  btn.disabled = true;
  showErrors(errs, []);
  try {
    S.settings = await api('PUT', '/settings', body);
    S.status = await api('GET', '/status');
    const enrolled = ((S.status && S.status.sites) || []).some((s) => s.gateway.enrolled);
    const moved = body.gateway && before.host && before.host !== body.gateway.host;
    toast(moved && enrolled ? 'Saved. Gateways already installed still dial the old address: re-enrol them from Sites & gateways.' : 'Saved');
    onSaved();
  } catch (e) {
    if (e.status !== 401) showErrors(errs, e.lines);
  } finally {
    btn.disabled = false;
  }
}

function enrolReset() {
  clearInterval(enrolTimer);
  enrolTimer = null;
  showErrors($('#enrol-errors'), []);
  for (const id of ['#enrol-prereq', '#enrol-main', '#enrol-ready', '#enrol-newcmd', '#enrol-live-sub']) $(id).hidden = true;
  $('#enrol-cmd').textContent = '';
  $('#enrol-note').textContent = '';
}

/** The gateway dialog while the controller isn't listening yet: ask where, then carry on. */
async function showListenerForm(afterSaved) {
  let settings;
  try {
    settings = await api('GET', '/settings');
    S.settings = settings;
  } catch (e) {
    if (e.status !== 401) showErrors($('#enrol-errors'), e.lines);
    return;
  }
  const c = gatewayControls(settings.gateway, afterSaved);
  $('#enrol-prereq').replaceChildren(
    h('p', null, 'Gateways dial in to this controller, and it isn\'t listening for them yet. Choose where it listens and we\'ll carry on.'),
    ...c.fields, c.actions);
  $('#enrol-prereq').hidden = false;
}

/** Just the listener controls, from the Sites page. */
async function openListenerHelp() {
  enrolSite = null;
  enrolReset();
  $('#enrol-title').textContent = 'Turn on gateways';
  openDialog('#enrol-dialog');
  await showListenerForm(() => $('#enrol-dialog').close());
}

async function openEnrol(site) {
  enrolSite = site;
  enrolReset();
  $('#enrol-title').textContent = `Connect a gateway for ${site.name}`;
  openDialog('#enrol-dialog');
  try {
    S.status = await api('GET', '/status');
  } catch (e) {
    if (e.status !== 401) showErrors($('#enrol-errors'), e.lines);
    return;
  }
  if (!S.status.gateway_listener) return showListenerForm(async () => { $('#enrol-prereq').hidden = true; await issueCommand(); });
  await issueCommand();
}

async function issueCommand() {
  showErrors($('#enrol-errors'), []);
  try {
    // What the site looked like before, so an old gateway's "connected" isn't mistaken for the new one.
    const now = (await api('GET', '/sites')).find((x) => x.id === enrolSite.id);
    enrolBaseline = now ? now.gateway.enrolled_at || null : null;
    const r = await api('POST', `/sites/${encodeURIComponent(enrolSite.id)}/enrol`);
    enrolExpires = r.expires;
    $('#enrol-cmd').textContent = r.command;
    $('#enrol-note').textContent = 'One-time command. It pins this controller\'s certificate, installs the gateway, and enrols it. Running a new command later replaces the gateway.';
    $('#enrol-main').hidden = false;
    $('#enrol-newcmd').hidden = true;
    $('#enrol-ready').hidden = true;
    setLive('warn', `Waiting for the gateway to connect… the command is valid for ${inFuture(enrolExpires)}.`);
    clearInterval(enrolTimer);
    enrolTimer = setInterval(pollEnrol, 2000);
  } catch (e) {
    if (e.status !== 401) showErrors($('#enrol-errors'), e.lines);
  }
}

function setLive(cls, text, sub) {
  $('#enrol-dot').className = 'dot ' + cls;
  $('#enrol-live-text').textContent = text;
  $('#enrol-live-sub').textContent = sub || '';
  $('#enrol-live-sub').hidden = !sub;
}

async function pollEnrol() {
  if (!enrolSite || !$('#enrol-dialog').open) return;
  let site;
  try {
    site = (await api('GET', '/sites')).find((x) => x.id === enrolSite.id);
  } catch (_) { return; }
  if (!site) return setLive('bad', 'This site no longer exists.');
  const g = site.gateway;
  const isNew = g.enrolled && (g.enrolled_at || null) !== enrolBaseline;
  if (isNew && g.online) {
    const up = g.tunnels.filter((t) => t.up).length;
    setLive('ok', 'Gateway connected.', g.tunnels.length
      ? `Tunnels to edges: ${up} of ${g.tunnels.length} up${g.error ? '. Gateway reports: ' + g.error : ''}.`
      : 'No edges have WireGuard yet, so there are no tunnels to show.');
    $('#enrol-ready').hidden = false;
    $('#enrol-newcmd').hidden = true;
  } else if (isNew) {
    setLive('warn', 'Gateway enrolled. Waiting for its first check-in…', g.error || '');
  } else if (g.enrol_pending_until) {
    enrolExpires = g.enrol_pending_until;
    setLive('warn', `Waiting for the gateway to connect… the command is valid for ${inFuture(enrolExpires)}.`);
  } else {
    setLive('bad', 'The command expired before a gateway used it.');
    $('#enrol-newcmd').hidden = false;
  }
}

$('#enrol-close').addEventListener('click', () => $('#enrol-dialog').close());
$('#enrol-dialog').addEventListener('close', () => { clearInterval(enrolTimer); enrolTimer = null; refresh(); });
$('#enrol-copy').addEventListener('click', () => { const text = $('#enrol-cmd').textContent; if (text) copyText(text); });
$('#enrol-newcmd').addEventListener('click', issueCommand);
$('#enrol-route').addEventListener('click', () => {
  const id = enrolSite && enrolSite.id;
  $('#enrol-dialog').close();
  setTab('routes');
  openRouteDialog(null);
  if (id) $('#r-site').value = id;
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
      h('div', { class: 'targets' }, c.targets.map((t) => h('div', { class: 'target mono' }, addr(t.address, t.port)))),
      c.site && h('div', { class: 'chips' }, h('span', { class: 'chip flag', title: 'Sent through this site\'s WireGuard gateway' }, 'via ' + siteName(c.site)))),
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

const routeBody = (c) => ({ id: c.id, name: c.name, enabled: c.enabled, listen: c.listen, domains: c.domains, targets: c.targets, proxy_protocol: c.proxy_protocol, edges: c.edges, site: c.site || null });

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
  const sites = (S.status && S.status.sites) || [];
  $('#r-site').replaceChildren(h('option', { value: '' }, 'None (targets reachable from the edge)'), ...sites.map((x) => h('option', { value: x.id }, `${x.name} (${x.lan_cidrs.join(', ')})`)));
  $('#r-site').value = c && c.site ? c.site : '';
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
    targets, proxy_protocol: $('#r-proxy').checked, site: $('#r-site').value || null,
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

  // WireGuard tunnels
  const hasSites = ((S.status && S.status.sites) || []).length > 0;
  const wgNet = h('input', { value: st.wg_network, spellcheck: 'false', disabled: hasSites });
  const wgPort = h('input', { value: st.wg_port, inputmode: 'numeric' });
  const wgErr = h('ul', { class: 'errors', hidden: true });
  const wgSave = h('button', { class: 'primary', type: 'button' }, 'Save');
  wgSave.addEventListener('click', () => saveSection(wgSave, wgErr, { wg_network: hasSites ? undefined : wgNet.value.trim(), wg_port: Number(wgPort.value) }));

  // Gateways
  const gwc = gatewayControls(st.gateway, () => renderPage(true));

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
    sectionForm('WireGuard tunnels', 'Edges and site gateways talk over private WireGuard tunnels inside this network. Every node gets an address from it.',
      [field('Tunnel network', wgNet, hasSites ? 'Fixed while sites exist, because every tunnel address would change.' : 'A private range between /16 and /27. It must not overlap any site\'s LAN ranges.'),
        field('Edge UDP port', wgPort, 'Each edge listens here for its gateways, so allow it in the provider firewall.'), wgErr],
      h('div', { class: 'buttons' }, wgSave)),
    sectionForm('Gateways', 'Lets WireGuard gateways on private networks (a home LAN, say) connect to this controller. Turning it on starts listening at once; no restart.',
      gwc.fields, gwc.actions),
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

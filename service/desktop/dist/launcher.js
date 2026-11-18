'use strict';
// The launcher talks to the app through four commands (see src-tauri/capabilities/launcher.json).
// Everything shown comes from those answers and is inserted as text, never as markup.
const invoke = (cmd, args) => window.__TAURI_INTERNALS__.invoke(cmd, args);
const $ = (sel) => document.querySelector(sel);

function node(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function fact(label, value, cls) {
  const dd = node('dd', cls, value);
  return [node('dt', null, label), dd];
}

function show(box, message) {
  box.textContent = message || '';
  box.hidden = !message;
}

function when(seconds) {
  return seconds ? new Date(seconds * 1000).toLocaleString() : 'never';
}

let busy = false;
function setBusy(on, label) {
  busy = on;
  for (const b of document.querySelectorAll('button, input')) b.disabled = on;
  $('#start-local').textContent = on && label === 'local' ? 'Starting…' : 'Start local controller';
  $('#connect-new').textContent = on && label === 'new' ? 'Connecting…' : 'Connect';
}

function render(state) {
  show($('#notice'), state.notice);

  const l = state.local;
  const facts = $('#local-facts');
  facts.replaceChildren(
    ...fact('Data folder', l.data_dir, 'mono'),
    ...fact('Account', l.has_data ? 'Existing data: you will sign in' : 'First run: you will create the administrator account', l.has_data ? '' : 'ok'),
    ...(l.agents.length
      ? fact('Can install on', l.agents.join(', ') + ' (Linux)')
      : fact('Can install on', 'nothing: no Linux builds found, so edges and gateways can’t be installed', 'warn')),
    ...fact('Gateways', l.gateway || 'listener off (turn it on in the controller\u2019s Settings, under Gateways)'),
    ...(l.running ? fact('Status', 'Running', 'ok') : []),
  );
  $('#start-local').textContent = l.running ? 'Open local controller' : 'Start local controller';

  const list = $('#remotes');
  list.replaceChildren();
  $('#no-remotes').hidden = state.remotes.length > 0;
  for (const r of state.remotes) {
    const who = node('div', 'who');
    who.append(node('div', 'name', r.name), node('div', 'url', r.url), node('div', 'when', 'Last connected: ' + when(r.last_used)));
    const connect = node('button', 'primary small', 'Connect');
    connect.type = 'button';
    connect.addEventListener('click', () => connectRemote(r.url, null, 'saved'));
    const forget = node('button', 'ghost small', 'Forget');
    forget.type = 'button';
    forget.title = 'Remove from this list (the controller itself is untouched)';
    forget.addEventListener('click', () => forgetRemote(r));
    const li = node('li');
    li.append(who, connect, forget);
    list.append(li);
  }
}

async function refresh() {
  try {
    render(await invoke('get_state'));
  } catch (e) {
    show($('#notice'), 'Could not load: ' + e);
  }
}

async function startLocal() {
  show($('#local-error'), '');
  setBusy(true, 'local');
  try {
    await invoke('start_local');
  } catch (e) {
    show($('#local-error'), String(e));
  }
  setBusy(false);
  await refresh();
}

async function connectRemote(url, name, which) {
  show($('#remote-error'), '');
  setBusy(true, which);
  try {
    await invoke('connect_remote', { url, name });
    $('#r-url').value = '';
    $('#r-name').value = '';
  } catch (e) {
    show($('#remote-error'), String(e));
  }
  setBusy(false);
  await refresh();
}

async function forgetRemote(r) {
  try {
    await invoke('forget_remote', { url: r.url });
  } catch (e) {
    show($('#remote-error'), String(e));
  }
  await refresh();
}

// ---- Set up a controller on a server ----------------------------------------------------------------

function syncSetupFields() {
  const access = $('#s-access').value;
  for (const f of document.querySelectorAll('#setup-form [data-for]')) f.hidden = f.dataset.for !== access;
  $('#s-gw-wrap').hidden = !$('#s-gateways').checked;
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Clipboard blocked: select the text so Ctrl+C works.
    const pre = button.parentElement.querySelector('pre');
    const range = document.createRange();
    range.selectNodeContents(pre);
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    button.textContent = 'Press Ctrl+C';
    setTimeout(() => { button.textContent = 'Copy'; }, 2500);
    return;
  }
  button.textContent = 'Copied';
  setTimeout(() => { button.textContent = 'Copy'; }, 1500);
}

function renderSteps(plan) {
  const list = $('#setup-steps');
  list.replaceChildren();
  for (const step of plan.steps) {
    const li = node('li');
    li.append(node('strong', null, step.title), node('p', null, step.note));
    if (step.command) {
      const box = node('div', 'cmd');
      const pre = node('pre', null, step.command);
      const copy = node('button', 'small', 'Copy');
      copy.type = 'button';
      copy.addEventListener('click', () => copyText(step.command, copy));
      box.append(pre, copy);
      li.append(box);
    }
    list.append(li);
  }
  list.hidden = false;
  $('#setup-connect').hidden = !plan.connect_url;
  if (plan.connect_url) {
    $('#setup-url').textContent = plan.connect_url;
    $('#setup-use').onclick = () => {
      $('#r-url').value = plan.connect_url;
      $('#r-url').scrollIntoView({ block: 'center' });
      $('#r-url').focus();
    };
  }
}

async function planSetup(ev) {
  ev.preventDefault();
  show($('#setup-error'), '');
  const val = (id) => $(id).value.trim() || null;
  try {
    renderSteps(await invoke('plan_setup', {
      request: {
        access: $('#s-access').value,
        login: val('#s-login'),
        private_ip: val('#s-private'),
        domain: val('#s-domain'),
        gateways: $('#s-gateways').checked,
        gateway_host: val('#s-gwhost'),
        root: $('#s-root').checked,
      },
    }));
  } catch (e) {
    $('#setup-steps').hidden = true;
    $('#setup-connect').hidden = true;
    show($('#setup-error'), String(e));
  }
}

$('#s-access').addEventListener('change', syncSetupFields);
$('#s-gateways').addEventListener('change', syncSetupFields);
$('#setup-form').addEventListener('submit', planSetup);
syncSetupFields();

$('#start-local').addEventListener('click', startLocal);
$('#remote-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  if (!busy) connectRemote($('#r-url').value, $('#r-name').value, 'new');
});
refresh();

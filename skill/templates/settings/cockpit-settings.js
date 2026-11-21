// Devices and sign out for the Cockpit settings page. Same-origin only:
// reads /auth/account and posts revocations with the session's CSRF token.
// Builds the page with textContent only. No third-party code.
(() => {
  'use strict';

  const API = '/auth/account';
  const statusEl = document.getElementById('status');
  let csrfToken = '';

  const setStatus = (text, isError = false) => {
    statusEl.textContent = text;
    statusEl.classList.toggle('error', isError);
  };

  const request = async (path, body) => {
    const init = { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } };
    if (body !== undefined) {
      init.method = 'POST';
      init.headers['Content-Type'] = 'application/json';
      init.headers['X-Cockpit-CSRF'] = csrfToken;
      init.body = JSON.stringify(body);
    }
    const res = await fetch(`${API}${path}`, init);
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) {
      const error = new Error(data?.error?.message ?? `Request failed (HTTP ${res.status}).`);
      error.status = res.status;
      throw error;
    }
    return data;
  };

  const el = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };

  const when = (value) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  };

  const button = (text, onClick) => {
    const node = el('button', text, 'secondary');
    node.type = 'button';
    node.addEventListener('click', async () => {
      node.disabled = true;
      try {
        await onClick();
      } catch (error) {
        setStatus(error.message || 'Something went wrong.', true);
      } finally {
        node.disabled = false;
      }
    });
    return node;
  };

  const signedOut = () => {
    document.getElementById('sessions-section').hidden = true;
    document.getElementById('users-section').hidden = true;
    document.getElementById('sign-in-link').hidden = false;
  };

  const revoke = async (session) => {
    const result = await request('/sessions/revoke', { session_id: session.id });
    if (result.current) {
      setStatus('Signed out on this device.');
      signedOut();
      return;
    }
    setStatus('Session revoked.');
    await load();
  };

  const sessionItem = (session) => {
    const item = el('li');
    item.append(el('strong', session.label || 'Unnamed device'));
    if (session.current) item.append(el('span', ' (this device)', 'hint'));
    item.append(el('div', `Signed in ${when(session.created_at)} · last seen ${when(session.last_seen_at)} · expires ${when(session.expires_at)}`, 'hint'));
    item.append(button(session.current ? 'Sign out' : 'Revoke', () => revoke(session)));
    return item;
  };

  const passkeyItem = (passkey) => {
    const item = el('li');
    item.append(el('strong', passkey.label || 'Unnamed passkey'));
    item.append(el('div', `Added ${when(passkey.created_at)}`, 'hint'));
    item.append(button('Remove passkey', async () => {
      const result = await request('/passkeys/remove', { credential_id: passkey.id });
      if (result.current) {
        setStatus('Passkey removed. This device was signed in with it and is now signed out.');
        signedOut();
        return;
      }
      setStatus(`Passkey removed; ${result.sessions_revoked} session(s) ended.`);
      await load();
    }));
    return item;
  };

  const renderUsers = (users) => {
    const container = document.getElementById('users');
    container.replaceChildren();
    for (const user of users) {
      const block = el('div', undefined, 'user');
      block.append(el('h3', `${user.display_name} (${user.role}${user.disabled ? ', disabled' : ''})`));
      block.append(el('h4', 'Sessions'));
      const sessions = el('ul', undefined, 'items');
      if (user.sessions.length === 0) sessions.append(el('li', 'No sessions.', 'hint'));
      for (const session of user.sessions) sessions.append(sessionItem(session));
      block.append(sessions);
      block.append(el('h4', 'Passkeys'));
      const passkeys = el('ul', undefined, 'items');
      if (user.passkeys.length === 0) passkeys.append(el('li', 'No passkeys.', 'hint'));
      for (const passkey of user.passkeys) passkeys.append(passkeyItem(passkey));
      block.append(passkeys);
      container.append(block);
    }
    document.getElementById('users-section').hidden = false;
  };

  const load = async () => {
    let account;
    try {
      account = await request('');
    } catch (error) {
      if (error.status === 401) {
        setStatus('You are not signed in with a passkey on this device.');
        signedOut();
        return;
      }
      throw error;
    }
    csrfToken = account.csrf_token;
    document.getElementById('signed-in-as').textContent = `Signed in as ${account.user.display_name} (${account.user.role}).`;
    const list = document.getElementById('sessions');
    list.replaceChildren(...account.sessions.map(sessionItem));
    document.getElementById('sessions-section').hidden = false;
    if (account.user.role === 'owner') renderUsers((await request('/users')).users);
  };

  const init = () => {
    const signOut = document.getElementById('sign-out');
    signOut.addEventListener('click', async () => {
      signOut.disabled = true;
      try {
        await request('/sign-out', {});
        setStatus('Signed out on this device.');
        signedOut();
      } catch (error) {
        setStatus(error.message || 'Sign-out failed.', true);
      } finally {
        signOut.disabled = false;
      }
    });
    load().catch((error) => setStatus(error.message || 'Could not load your devices.', true));
  };

  init();
})();

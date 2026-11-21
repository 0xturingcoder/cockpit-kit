// Devices, passkeys, invites, recovery activity, and sign out for the
// Cockpit settings page. Same-origin only: reads /auth/account and posts
// changes with the session's CSRF token; adding a passkey and the passkey
// step-up use /auth/passkey/* and the browser's native navigator.credentials.
// When an action needs a fresh step-up (403 step_up_required) the page asks
// for a passkey and retries once. Builds the page with textContent only. A new
// invite link is shown once and kept only in the page. No third-party code.
(() => {
  'use strict';

  const API = '/auth/account';
  const PASSKEY_API = '/auth/passkey';
  const statusEl = document.getElementById('status');
  let csrfToken = '';

  const setStatus = (text, isError = false) => {
    statusEl.textContent = text;
    statusEl.classList.toggle('error', isError);
  };

  const request = async (path, body, base = API) => {
    const init = { credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer', headers: { Accept: 'application/json' } };
    if (body !== undefined) {
      init.method = 'POST';
      init.headers['Content-Type'] = 'application/json';
      init.headers['X-Cockpit-CSRF'] = csrfToken;
      init.body = JSON.stringify(body);
    }
    const res = await fetch(`${base}${path}`, init);
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) {
      const error = new Error(data?.error?.message ?? `Request failed (HTTP ${res.status}).`);
      error.status = res.status;
      error.code = data?.error?.code;
      throw error;
    }
    return data;
  };

  const passkeyRequest = (path, body) => request(path, body, PASSKEY_API);

  // base64url <-> ArrayBuffer, unpadded, as the server sends and expects.
  const fromBase64url = (value) => {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  };

  const toBase64url = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const describe = (error) => {
    if (error?.name === 'NotAllowedError') return 'The passkey prompt was cancelled or timed out.';
    if (error?.name === 'InvalidStateError') return 'This device already has a passkey for this Cockpit.';
    return error?.message || 'Something went wrong.';
  };

  // A fresh passkey verification for this session (an owner passkey).
  const stepUp = async () => {
    setStatus('Confirm with one of your passkeys…');
    const options = await passkeyRequest('/step-up/options', {});
    const publicKey = {
      ...options.publicKey,
      challenge: fromBase64url(options.publicKey.challenge),
      allowCredentials: (options.publicKey.allowCredentials ?? []).map((item) => ({ ...item, id: fromBase64url(item.id) })),
    };
    const credential = await navigator.credentials.get({ publicKey });
    await passkeyRequest('/step-up/verify', {
      challenge_id: options.challenge_id,
      credential: {
        id: credential.id,
        rawId: toBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toBase64url(credential.response.clientDataJSON),
          authenticatorData: toBase64url(credential.response.authenticatorData),
          signature: toBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? toBase64url(credential.response.userHandle) : null,
        },
        authenticatorAttachment: credential.authenticatorAttachment ?? null,
        clientExtensionResults: credential.getClientExtensionResults(),
      },
    });
  };

  // Run `action`; if the server wants a fresh step-up, do one and retry once.
  const withStepUp = async (action) => {
    try {
      return await action();
    } catch (error) {
      if (error.code !== 'step_up_required') throw error;
      await stepUp();
      return action();
    }
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
    document.getElementById('invites-section').hidden = true;
    document.getElementById('passkey-section').hidden = true;
    document.getElementById('audit-section').hidden = true;
    document.getElementById('recovery-banner').hidden = true;
    hideInviteLink();
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
    if (session.kind === 'recovery') item.append(el('span', ' (recovery token)', 'hint'));
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

  const hideInviteLink = () => {
    document.getElementById('invite-url').value = '';
    document.getElementById('invite-result').hidden = true;
  };

  const inviteItem = (invite) => {
    const item = el('li');
    item.append(el('strong', invite.display_name));
    item.append(el('div', `Created ${when(invite.created_at)} · expires ${when(invite.expires_at)}`, 'hint'));
    item.append(button('Revoke invite', async () => {
      await request('/invites/revoke', { invite_id: invite.id });
      setStatus('Invite revoked.');
      await loadInvites();
    }));
    return item;
  };

  const loadInvites = async () => {
    const { invites } = await request('/invites');
    const list = document.getElementById('invites');
    list.replaceChildren(...invites.map(inviteItem));
    if (invites.length === 0) list.append(el('li', 'No pending invites.', 'hint'));
    document.getElementById('invites-section').hidden = false;
  };

  const createInvite = async (form, submit) => {
    submit.disabled = true;
    hideInviteLink();
    try {
      const displayName = form.elements.display_name.value.trim();
      const result = await withStepUp(() => request('/invites', { display_name: displayName }));
      document.getElementById('invite-url').value = result.url;
      document.getElementById('invite-result').hidden = false;
      form.reset();
      setStatus(`Invite created for ${result.invite.display_name}. Copy the link now; it is not shown again.`);
      await loadInvites();
    } catch (error) {
      setStatus(describe(error) || 'Could not create the invite.', true);
    } finally {
      submit.disabled = false;
    }
  };

  // Add an owner passkey from this session, stepping up first when needed.
  const addPasskey = async (form, submit) => {
    submit.disabled = true;
    try {
      const options = await withStepUp(() => passkeyRequest('/register/options', {}));
      setStatus('Waiting for your new authenticator…');
      const publicKey = {
        ...options.publicKey,
        challenge: fromBase64url(options.publicKey.challenge),
        user: { ...options.publicKey.user, id: fromBase64url(options.publicKey.user.id) },
        excludeCredentials: (options.publicKey.excludeCredentials ?? []).map((item) => ({ ...item, id: fromBase64url(item.id) })),
      };
      const credential = await navigator.credentials.create({ publicKey });
      const body = {
        challenge_id: options.challenge_id,
        credential: {
          id: credential.id,
          rawId: toBase64url(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: toBase64url(credential.response.clientDataJSON),
            attestationObject: toBase64url(credential.response.attestationObject),
            transports: typeof credential.response.getTransports === 'function' ? credential.response.getTransports() : [],
          },
          authenticatorAttachment: credential.authenticatorAttachment ?? null,
          clientExtensionResults: credential.getClientExtensionResults(),
        },
      };
      const label = form.elements.label.value.trim();
      if (label) body.label = label;
      await passkeyRequest('/register/verify', body);
      form.reset();
      setStatus('Passkey added.');
      await load();
    } catch (error) {
      setStatus(describe(error), true);
    } finally {
      submit.disabled = false;
    }
  };

  const EVENTS = {
    token_sign_in: 'Recovery token sign-in',
    token_rotated: 'Recovery token rotated',
    first_owner: 'Owner created with the recovery token',
    recovery_enroll: 'Passkey added during recovery enrollment',
  };
  const RESULTS = {
    ok: 'succeeded', invalid: 'wrong token', rate_limited: 'rate limited', no_owner: 'no owner yet', owner_exists: 'owner already exists',
  };

  const loadAudit = async () => {
    const { events } = await request('/audit');
    const list = document.getElementById('audit');
    list.replaceChildren(...events.map((entry) => el('li', `${when(entry.at)} · ${EVENTS[entry.event] ?? entry.event} · ${RESULTS[entry.result] ?? entry.result}`)));
    if (events.length === 0) list.append(el('li', 'No recovery activity.', 'hint'));
    document.getElementById('audit-section').hidden = false;
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
    const current = account.sessions.find((session) => session.current);
    document.getElementById('recovery-banner').hidden = current?.kind !== 'recovery';
    if (account.user.role === 'owner') {
      document.getElementById('passkey-section').hidden = !(window.PublicKeyCredential && navigator.credentials);
      renderUsers((await request('/users')).users);
      await loadInvites();
      await loadAudit();
    }
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
    const passkeyForm = document.getElementById('passkey-form');
    passkeyForm.addEventListener('submit', (event) => {
      event.preventDefault();
      addPasskey(passkeyForm, document.getElementById('passkey-add'));
    });
    const inviteForm = document.getElementById('invite-form');
    inviteForm.addEventListener('submit', (event) => {
      event.preventDefault();
      createInvite(inviteForm, document.getElementById('invite-create'));
    });
    // Do not keep a shown link in the back/forward cache.
    window.addEventListener('pagehide', hideInviteLink);
    const copy = document.getElementById('invite-copy');
    copy.addEventListener('click', async () => {
      const input = document.getElementById('invite-url');
      try {
        await navigator.clipboard.writeText(input.value);
        setStatus('Invite link copied.');
      } catch {
        input.select();
        setStatus('Select the link and copy it.');
      }
    });
    load().catch((error) => setStatus(error.message || 'Could not load your devices.', true));
  };

  init();
})();

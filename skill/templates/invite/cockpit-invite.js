// Invite enrollment for the Cockpit invite page. The invite token arrives in
// the URL fragment (/auth/invite/#<token>), which browsers never send to a
// server or put in a Referer. This script takes it, removes it from the
// address bar and history before any request, keeps it only in memory, and
// sends it only in POST bodies to /auth/passkey/invite/* on this server.
// No third-party code.
(() => {
  'use strict';

  // Take the token and strip the fragment first, before anything else runs.
  const token = window.location.hash.slice(1);
  if (window.location.hash) window.history.replaceState(null, '', window.location.pathname);

  const API = '/auth/passkey';
  const statusEl = document.getElementById('status');

  const setStatus = (text, isError = false) => {
    statusEl.textContent = text;
    statusEl.classList.toggle('error', isError);
  };

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

  const post = async (path, body) => {
    const res = await fetch(`${API}${path}`, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) {
      const error = new Error(data?.error?.message ?? `Request failed (HTTP ${res.status}).`);
      error.code = data?.error?.code;
      error.status = res.status;
      throw error;
    }
    return data;
  };

  const creationOptions = (publicKey) => ({
    ...publicKey,
    challenge: fromBase64url(publicKey.challenge),
    user: { ...publicKey.user, id: fromBase64url(publicKey.user.id) },
    excludeCredentials: (publicKey.excludeCredentials ?? []).map((item) => ({ ...item, id: fromBase64url(item.id) })),
  });

  const registrationJson = (credential) => ({
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
  });

  const INVALID = 'This invite link is not valid. It may have expired, been used, or been revoked. Ask the owner for a new one.';

  const describe = (error) => {
    if (error?.code === 'invite_invalid') return INVALID;
    if (error?.name === 'NotAllowedError') return 'The passkey prompt was cancelled or timed out. Try again.';
    if (error?.name === 'InvalidStateError') return 'This authenticator already has a passkey for this Cockpit.';
    if (error?.name === 'SecurityError') return 'Passkeys are not available on this address. Open the invite link exactly as you received it.';
    return error?.message || 'Something went wrong.';
  };

  const finished = () => {
    document.getElementById('enroll-section').hidden = true;
    document.getElementById('sign-in-link').hidden = false;
  };

  const enroll = async (form, button) => {
    button.disabled = true;
    setStatus('Waiting for your authenticator…');
    try {
      const options = await post('/invite/options', { token });
      const credential = await navigator.credentials.create({ publicKey: creationOptions(options.publicKey) });
      const body = { token, challenge_id: options.challenge_id, credential: registrationJson(credential) };
      const label = form.elements.label.value.trim();
      if (label) body.label = label;
      const result = await post('/invite/verify', body);
      finished();
      if (result.signed_in) {
        setStatus('Passkey created. Opening Cockpit…');
        window.location.assign('/');
      } else {
        setStatus('Passkey created. Sign in with it to continue.');
      }
    } catch (error) {
      setStatus(describe(error), true);
      if (error?.code === 'invite_invalid') finished();
      button.disabled = false;
    }
  };

  const init = () => {
    const form = document.getElementById('enroll-form');
    const button = document.getElementById('enroll');
    if (!token) {
      setStatus('Open the full invite link you received. If you already used it, sign in instead.', true);
      finished();
      return;
    }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      setStatus('This browser does not support passkeys.', true);
      button.disabled = true;
      return;
    }
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      enroll(form, button);
    });
  };

  init();
})();

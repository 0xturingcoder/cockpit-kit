// Passkey sign-in, recovery-token sign-in, and first-owner setup for the
// Cockpit login page. Same-origin only: talks to /auth/passkey/* on this
// server through fetch and the browser's native navigator.credentials API.
// The recovery token is read from a password field, sent only in POST bodies,
// and never put in a URL, storage, or the console; the field is cleared after
// each attempt. No third-party code.
(() => {
  'use strict';

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

  const requestOptions = (publicKey) => ({
    ...publicKey,
    challenge: fromBase64url(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials ?? []).map((item) => ({ ...item, id: fromBase64url(item.id) })),
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

  const authenticationJson = (credential) => ({
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
  });

  const describe = (error) => {
    if (error?.name === 'NotAllowedError') return 'The passkey prompt was cancelled or timed out.';
    if (error?.name === 'InvalidStateError') return 'This device already has a passkey for this Cockpit.';
    if (error?.name === 'SecurityError') return 'Passkeys are not available on this address. Use the address the server printed for passkeys.';
    return error?.message || 'Something went wrong.';
  };

  const busy = (button, flag) => { button.disabled = flag; };

  const signIn = async (button) => {
    busy(button, true);
    setStatus('Waiting for your passkey…');
    try {
      const options = await post('/login/options', {});
      const credential = await navigator.credentials.get({ publicKey: requestOptions(options.publicKey) });
      await post('/login/verify', { challenge_id: options.challenge_id, credential: authenticationJson(credential) });
      setStatus('Signed in. Opening Cockpit…');
      window.location.assign('/');
    } catch (error) {
      setStatus(describe(error), true);
    } finally {
      busy(button, false);
    }
  };

  const recover = async (form, button) => {
    const input = form.elements.token;
    const token = input.value.trim();
    input.value = '';
    if (!token) {
      setStatus('Enter the recovery token.', true);
      return;
    }
    busy(button, true);
    setStatus('Checking the recovery token…');
    try {
      await post('/recovery/sign-in', { token });
      setStatus('Signed in with the recovery token. Opening Devices…');
      window.location.assign('/auth/settings/');
    } catch (error) {
      if (error?.code === 'no_owner') setStatus('There is no owner yet. Create the owner below.', true);
      else setStatus(describe(error), true);
    } finally {
      busy(button, false);
    }
  };

  // First-owner setup: the recovery token goes in both POST bodies and is
  // accepted only while there is no owner.
  const setup = async (form, button) => {
    const input = form.elements.recovery_token;
    const token = input.value.trim();
    input.value = '';
    if (!token) {
      setStatus('Enter the recovery token the server created.', true);
      return;
    }
    busy(button, true);
    setStatus('Waiting for your authenticator…');
    try {
      const displayName = form.elements.display_name.value.trim();
      const options = await post('/register/options', { display_name: displayName, recovery_token: token });
      const credential = await navigator.credentials.create({ publicKey: creationOptions(options.publicKey) });
      const body = { challenge_id: options.challenge_id, credential: registrationJson(credential), recovery_token: token };
      const label = form.elements.label.value.trim();
      if (label) body.label = label;
      await post('/register/verify', body);
      setStatus('Owner created. You can now sign in with your passkey.');
      form.reset();
    } catch (error) {
      if (error?.code === 'owner_exists') setStatus('The owner already exists. Sign in, then add passkeys from Devices.', true);
      else setStatus(describe(error), true);
    } finally {
      busy(button, false);
    }
  };

  const init = () => {
    const signInButton = document.getElementById('sign-in');
    const recoverForm = document.getElementById('recover-form');
    const recoverButton = document.getElementById('recover');
    const setupForm = document.getElementById('setup-form');
    const setupButton = document.getElementById('setup');
    recoverForm.addEventListener('submit', (event) => {
      event.preventDefault();
      recover(recoverForm, recoverButton);
    });
    if (!window.PublicKeyCredential || !navigator.credentials) {
      setStatus('This browser does not support passkeys.', true);
      signInButton.disabled = true;
      setupButton.disabled = true;
      return;
    }
    signInButton.addEventListener('click', () => signIn(signInButton));
    setupForm.addEventListener('submit', (event) => {
      event.preventDefault();
      setup(setupForm, setupButton);
    });
  };

  init();
})();

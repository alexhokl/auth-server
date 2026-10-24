const passkeyLoginUrl = '/fido/signin/passkey/challenge';
const passkeyLoginCallbackUrl = '/fido/signin/passkey';
const passkeyButton = document.getElementById('passkey');
const passkeyError = document.getElementById('passkey-error');
const signInForm = document.getElementById('signin');

// all sign-in flows share a single WebAuthn session on the server and each
// challenge overwrites the previous one, thus challenge requests are chained
// so that they never overlap
let pendingChallenge = Promise.resolve();
// aborts the pending conditional (autofill) request
let conditionalAbortController = null;

// PasskeyRejectedError is thrown when the server rejects an assertion.
class PasskeyRejectedError extends Error {
  constructor(cause) {
    super('Passkey sign-in has been rejected', { cause: cause });
    this.name = 'PasskeyRejectedError';
  }
}

const abortError = () => new DOMException('Passkey request has been aborted', 'AbortError');

const requestPasskeyChallenge = () => {
  const previous = pendingChallenge;
  const current = (async () => {
    await previous.catch(() => {});
    // posted without a query string; the redirect is followed on the client,
    // as fetch would follow a redirect of the server silently
    const response = await post(passkeyLoginUrl);
    return await parseJsonResponse(response);
  })();
  pendingChallenge = current;
  return current;
};

// loginByPasskey signs in with a discoverable credential and returns true if
// it has been signed in. mediation is either undefined, for a modal request,
// or 'conditional', for autofill.
const loginByPasskey = async (mediation) => {
  let signal;
  if (mediation === 'conditional') {
    conditionalAbortController = new AbortController();
    signal = conditionalAbortController.signal;
  }

  const data = await requestPasskeyChallenge();
  if (signal?.aborted) {
    throw abortError();
  }

  const resp = data.publicKey;
  const options = {
    publicKey: {
      // pairs with the re-encoding of the challenge on the server
      challenge: Uint8Array.from(resp.challenge, c => c.charCodeAt(0)),
      rpId: resp.rpId,
      timeout: resp.timeout,
      userVerification: resp.userVerification,
    },
  };
  if (signal) {
    options.mediation = mediation;
    options.signal = signal;
  }

  const credentials = await navigator.credentials.get(options);
  if (!credentials) {
    return false;
  }
  const params = {
    id: credentials.id,
    type: credentials.type,
    rawId: base64UrlEncode(credentials.rawId),
    response: {
      clientDataJSON: base64UrlEncode(credentials.response.clientDataJSON),
      authenticatorData: base64UrlEncode(credentials.response.authenticatorData),
      signature: base64UrlEncode(credentials.response.signature),
      userHandle: base64UrlEncode(credentials.response.userHandle),
    },
  };
  try {
    await post(passkeyLoginCallbackUrl, params);
  } catch (err) {
    throw new PasskeyRejectedError(err);
  }
  console.info('Login has been completed.');
  const urlParams = new URLSearchParams(window.location.search);
  const redirectUri = urlParams.get('redirect_uri');
  window.location.href = isSafeRedirectUri(redirectUri) ? redirectUri : '/authenticated';
  return true;
};

const abortConditionalPasskey = () => {
  if (conditionalAbortController) {
    conditionalAbortController.abort();
    conditionalAbortController = null;
  }
};

const isConditionalMediationAvailable = async () => {
  try {
    return !!(await window.PublicKeyCredential?.isConditionalMediationAvailable?.());
  } catch (err) {
    return false;
  }
};

const showPasskeyError = (message) => {
  passkeyError.textContent = message;
  passkeyError.hidden = !message;
};

// startConditionalPasskey offers passkeys in the autofill of the email field.
const startConditionalPasskey = async () => {
  if (!(await isConditionalMediationAvailable())) {
    return;
  }
  try {
    await loginByPasskey('conditional');
  } catch (err) {
    // aborted for a modal request or a form submit, which fetch a challenge
    // of their own; restarting would overwrite it
    if (err.name === 'AbortError') {
      return;
    }
    console.warn('Passkey autofill failed', err);
    if (err instanceof PasskeyRejectedError) {
      showPasskeyError('Sign-in with the passkey failed.');
      startConditionalPasskey();
    }
  }
};

const signInWithPasskey = async () => {
  abortConditionalPasskey();
  showPasskeyError('');
  let signedIn = false;
  try {
    signedIn = await loginByPasskey();
  } catch (err) {
    console.warn('Passkey sign-in failed', err);
    if (err.name !== 'NotAllowedError' && err.name !== 'AbortError') {
      showPasskeyError('Sign-in with a passkey failed.');
    }
  }
  if (!signedIn) {
    startConditionalPasskey();
  }
};

if (window.PublicKeyCredential) {
  passkeyButton.hidden = false;
  passkeyButton.addEventListener('click', signInWithPasskey);
  signInForm.addEventListener('submit', abortConditionalPasskey);
  startConditionalPasskey();
}

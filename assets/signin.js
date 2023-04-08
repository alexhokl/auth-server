const loginUrl = '/fido/signin/challenge';
const loginCallbackUrl = '/fido/signin';
const passwordInput = document.getElementById('current-password');
const togglePasswordButton = document.getElementById('toggle-password');

const togglePassword = () => {
  if (passwordInput.type === 'password') {
    passwordInput.type = 'text';
    togglePasswordButton.textContent = 'Hide password';
    togglePasswordButton.setAttribute('aria-label',
      'Hide password.');
  } else {
    passwordInput.type = 'password';
    togglePasswordButton.textContent = 'Show password';
    togglePasswordButton.setAttribute('aria-label',
      'Show password as plain text. ' +
      'Warning: this will display your password on the screen.');
  }
}

const loginByKey = async () => {
  const response = await post(loginUrl);
  const data = await parseJsonResponse(response);

  const resp = data.publicKey;
  const publicKeyRetrievalOptions = {
    challenge: Uint8Array.from(resp.challenge, c => c.charCodeAt(0)),
    allowCredentials: resp.allowCredentials.map(cred => {
      return {
        id: base64UrlDecode(cred.id),
        type: cred.type,
      }
    }),
    timeout: resp.timeout,
  };

  const credentials = await navigator.credentials.get({ publicKey: publicKeyRetrievalOptions });
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
  await post(loginCallbackUrl, params);
  console.info('Login has been completed.');
  const urlParams = new URLSearchParams(window.location.search);
  const redirectUri = urlParams.get('redirect_url');
  window.location.href = redirectUri;
};

togglePasswordButton.addEventListener('click', togglePassword);

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

const loginByKey = () => {
  post(loginUrl)
    .then(parseJsonResponse)
    .then(data => {
      const resp = data.publicKey;
      resp.allowCredentials.forEach(cred => {
        console.info('Credential ID', cred.id.concat("=").replace(/_/g, '/').replace(/-/g, '+'));
      });
      const publicKey = {
        challenge: Uint8Array.from(resp.challenge, c => c.charCodeAt(0)),
        allowCredentials: resp.allowCredentials.map(cred => {
          return {
            id: Uint8Array.from(cred.id.concat("=").replace(/_/g, '/').replace(/-/g, '+'), c => c.charCodeAt(0)),
            type: cred.type,
          }
        }),
        timeout: resp.timeout,
      };

      navigator.credentials.get({ publicKey })
        .then(credentials => {
          const params = {
            id: credentials.id,
            type: credentials.type,
            rawId: base64UrlEncode(credentials.rawId),
            response: {
              clientDataJSON: base64UrlEncode(credentials.response.clientDataJSON),
              attestationObject: base64UrlEncode(credentials.response.attestationObject),
            },
          };
          post(loginCallbackUrl, params)
            .then(response =>  {
              console.info('Login has been completed.');
            })
            .catch(response => {
              console.error('Login failed', error);
            });
        })
        .catch(error => {
          console.error('Failed to start login', error);
        });
    })
    .catch(error => {
      console.error('Failed to kickstart login', error);
    });
};

togglePasswordButton.addEventListener('click', togglePassword);

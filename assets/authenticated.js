const registerUrl = '/fido/register/challenge';
const registerCallbackUrl = '/fido/register';

const isWebAuthnSupported = async () => {
  if (window.PublicKeyCredential &&
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
    PublicKeyCredential.isConditionalMediationAvailable) {
    // Check if user verifying platform authenticator is available.
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable() &&
      await PublicKeyCredential.isConditionalMediationAvailable();
  }
  return false;
}

const registerKey = () => {
  post(registerUrl)
    .then(parseJsonResponse)
    .then(data => {
      const resp = data.publicKey;
      const attestation = 'direct';
      const publicKey = {
        challenge: Uint8Array.from(resp.challenge, c => c.charCodeAt(0)),
        pubKeyCredParams: resp.pubKeyCredParams,
        rp: resp.rp,
        user: {
          id: Uint8Array.from(resp.user.id, c => c.charCodeAt(0)),
          name: resp.user.name,
          displayName: resp.user.displayName,
        },
        timeout: resp.timeout,
        attestation: attestation,
      };

      navigator.credentials.create({ publicKey })
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

          post(registerCallbackUrl, params)
            .then(response => {
              console.info(`Registration ${params.id} completed.`);
            })
            .catch(error => {
              console.error('Failed to register', error);
            });
        })
        .catch(error => {
          console.error('Failed to start registration', error);
        });
    })
    .catch(error => {
      console.error('Failed to kickstart registration', error);
    });
};

const signOut = () => {
  fetch('/signout', {
    method: 'post',
  }).then(response => {
    window.location.href = '/';
  }).catch(error => {
    console.log(error);
  });
}

isWebAuthnSupported().then(supported => {
  console.info('is webauthn supported?', supported);
});

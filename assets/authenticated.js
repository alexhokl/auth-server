const registerUrl = '/fido/register/challenge';
const registerCallbackUrl = '/fido/register';
const credentialsUrl = '/fido/credentials';

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

const showRegisterError = (message) => {
  const registerError = document.getElementById('register-error');
  registerError.textContent = message;
  registerError.hidden = !message;
};

const registerKey = async () => {
  showRegisterError('');
  try {
    await createKey();
  } catch (err) {
    console.warn('Registration failed', err);
    if (err.name === 'InvalidStateError') {
      // the authenticator holds one of the excluded credentials
      showRegisterError('This passkey or key is already registered.');
    } else if (err.name !== 'NotAllowedError') {
      showRegisterError('Registration of the passkey or key failed.');
    }
  }
};

const createKey = async () => {
  const response = await post(registerUrl);
  const data = await parseJsonResponse(response);

  const resp = data.publicKey;
  const publicKeyCreationOptions = {
    challenge: Uint8Array.from(resp.challenge, c => c.charCodeAt(0)),
    pubKeyCredParams: resp.pubKeyCredParams,
    rp: resp.rp,
    user: {
      // user.id is the base64url encoding of the user handle; unlike the
      // challenge, there is no re-encoding on the server
      id: base64UrlDecode(resp.user.id),
      name: resp.user.name,
      displayName: resp.user.displayName,
    },
    timeout: resp.timeout,
    attestation: resp.attestation,
    authenticatorSelection: resp.authenticatorSelection,
    // without it, a passkey provider would replace the passkey of the user
    // and leave the registered credential orphaned
    excludeCredentials: (resp.excludeCredentials ?? []).map(cred => {
      return {
        id: base64UrlDecode(cred.id),
        type: cred.type,
        transports: cred.transports,
      }
    }),
  };

  const credentials = await navigator.credentials.create({ publicKey: publicKeyCreationOptions });
  const params = {
    id: credentials.id,
    type: credentials.type,
    rawId: base64UrlEncode(credentials.rawId),
    authenticatorAttachment: credentials.authenticatorAttachment,
    response: {
      clientDataJSON: base64UrlEncode(credentials.response.clientDataJSON),
      attestationObject: base64UrlEncode(credentials.response.attestationObject),
      transports: credentials.response.getTransports?.() ?? [],
    },
  };

  await post(registerCallbackUrl, params);
  console.info(`Registration ${params.id} completed.`);

  const keys = await getKeys();
  writeKeyTable(keys);
};

const getKeys = async () => {
  const response = await get(credentialsUrl);
  return await parseJsonResponse(response);
};

const writeKeyTable = (keys) => {
  const tableBody = document.getElementById('key_table_body');

  // remove all rows
  tableBody.innerHTML = '';

  if (!keys || keys.length === 0) {
    return;
  }

  keys.forEach((k, index) => {
    let row = document.createElement('tr');
    let nameCell = document.createElement('td');
    let idCell = document.createElement('td');
    let syncedCell = document.createElement('td');
    let actionsCell = document.createElement('td');

    nameCell.innerHTML = `<input type="text" id="key_name_${index}" value="${k.name}"/>`;
    idCell.innerText = k.id;
    syncedCell.innerText = k.backup_eligible ? 'Yes' : 'No';
    actionsCell.innerHTML = `<button onclick="deleteKey('${k.id}')">Delete</button><button onclick="updateKey('${k.id}', 'key_name_${index}')">Update</button>`;

    row.appendChild(nameCell);
    row.appendChild(idCell);
    row.appendChild(syncedCell);
    row.appendChild(actionsCell);

    tableBody.appendChild(row);
  });
};

const deleteKey = async (id) => {
  await deleteResource(credentialsUrl, base64ToBase64Url(id));
  const keys = await getKeys();
  writeKeyTable(keys);
}

const updateKey = async (id, nameElementId) => {
  const name = document.getElementById(nameElementId).value;
  const params = {
    name: name,
  };

  await patch(credentialsUrl, base64ToBase64Url(id), params);
  const keys = await getKeys();
  writeKeyTable(keys);
}

const signOut = async () => {
  await fetch('/signout', { method: 'post' });
  window.location.href = '/';
};

const changePassword = () => {
  window.location.href = '/changepassword';
}

isWebAuthnSupported().then(supported => {
  console.info('is webauthn supported?', supported);
});

getKeys().then(keys => {
  writeKeyTable(keys);
});

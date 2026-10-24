import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import {
  bytes,
  domException,
  errorResponse,
  fakeCredentials,
  fakeFetch,
  flush,
  jsonResponse,
  loadPage,
  origin,
  toArray,
} from './helpers.js';

const credentialsUrl = '/fido/credentials';
const registerChallengeUrl = '/fido/register/challenge';
const registerUrl = '/fido/register';

const laptop = { id: 'ab+c/d==', name: 'Laptop', backup_eligible: true };
const securityKey = { id: 'xyz', name: 'Security key', backup_eligible: false };

const registerChallenge = {
  publicKey: {
    challenge: 'abc',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    rp: { id: 'auth.example.com', name: 'Auth Server' },
    user: { id: '__79', name: 'alex@test.com', displayName: 'Alex' },
    timeout: 60000,
    attestation: 'none',
    authenticatorSelection: { residentKey: 'required' },
    excludeCredentials: [{ id: '-_8', type: 'public-key', transports: ['usb'] }],
  },
};

const attestationCredential = ({ withTransports = true } = {}) => ({
  id: 'new-id',
  type: 'public-key',
  rawId: bytes(1, 2, 3),
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: bytes(4, 5),
    attestationObject: bytes(6),
    ...(withTransports ? { getTransports: () => ['internal', 'hybrid'] } : {}),
  },
});

describe('authenticated.js', () => {
  let page;
  // keys is what the server returns for the credentials of the user
  let keys;

  const load = ({ challenge = registerChallenge, create = async () => attestationCredential(), publicKeyCredential } = {}) => {
    const fetch = fakeFetch((call) => {
      if (call.method === 'GET' && call.url === credentialsUrl) {
        return jsonResponse(keys);
      }
      if (call.method === 'POST' && call.url === registerChallengeUrl) {
        return challenge ? jsonResponse(challenge) : errorResponse(500, 'Internal Server Error');
      }
      if (call.method === 'POST' && call.url === registerUrl) {
        keys = [...keys, { id: call.body.id, name: 'New', backup_eligible: false }];
        return jsonResponse({});
      }
      if (call.url.startsWith(`${credentialsUrl}/`) || call.url === '/signout') {
        return jsonResponse({});
      }
      return errorResponse(404, 'Not Found');
    });
    page = loadPage({
      page: 'authenticated.html',
      scripts: ['http.js', 'authenticated.js'],
      url: `${origin}/authenticated`,
      fetch,
      credentials: fakeCredentials({ create }),
      publicKeyCredential,
    });
    return page;
  };

  // innerText is not implemented by jsdom, thus it is read back as set
  const rows = () => Array.from(page.document.querySelectorAll('#key_table_body tr')).map(row => ({
    name: row.cells[0].querySelector('input').value,
    id: row.cells[1].innerText,
    synced: row.cells[2].innerText,
  }));

  const registerError = () => page.document.getElementById('register-error');

  afterEach(() => {
    page?.close();
    keys = [];
  });

  describe('key table', () => {
    it('lists the keys of the user on load', async () => {
      keys = [laptop, securityKey];
      const { fetch } = load();
      await flush();

      assert.deepEqual(fetch.to('GET', credentialsUrl).length, 1);
      assert.deepEqual(rows(), [
        { name: 'Laptop', id: 'ab+c/d==', synced: 'Yes' },
        { name: 'Security key', id: 'xyz', synced: 'No' },
      ]);
      assert.equal(page.document.getElementById('key_name_1').value, 'Security key');
    });

    for (const [name, value] of [['empty', []], ['null', null], ['undefined', undefined]]) {
      it(`clears the table for ${name} keys`, async () => {
        keys = [laptop];
        const { g } = load();
        await flush();

        g('writeKeyTable')(value);

        assert.deepEqual(rows(), []);
      });
    }

    it('replaces the rows on each write', async () => {
      keys = [laptop, securityKey];
      const { g } = load();
      await flush();

      g('writeKeyTable')([securityKey]);

      assert.deepEqual(rows(), [{ name: 'Security key', id: 'xyz', synced: 'No' }]);
    });
  });

  describe('registerKey', () => {
    it('creates a credential with the options of the server', async () => {
      const { g, credentials } = load();
      await flush();

      await g('registerKey')();

      assert.equal(credentials.createCalls.length, 1);
      const options = credentials.createCalls[0].publicKey;
      assert.deepEqual(toArray(options.challenge), [97, 98, 99]);
      assert.deepEqual(options.pubKeyCredParams, registerChallenge.publicKey.pubKeyCredParams);
      assert.deepEqual(options.rp, registerChallenge.publicKey.rp);
      assert.deepEqual(toArray(options.user.id), [0xff, 0xfe, 0xfd]);
      assert.equal(options.user.name, 'alex@test.com');
      assert.equal(options.user.displayName, 'Alex');
      assert.equal(options.timeout, 60000);
      assert.equal(options.attestation, 'none');
      assert.deepEqual(options.authenticatorSelection, { residentKey: 'required' });
      assert.deepEqual(options.excludeCredentials.map(c => [toArray(c.id), c.type, c.transports]), [
        [[0xfb, 0xff], 'public-key', ['usb']],
      ]);
    });

    it('excludes no credentials when the server lists none', async () => {
      const { excludeCredentials, ...withoutExclusions } = registerChallenge.publicKey;
      const { g, credentials } = load({ challenge: { publicKey: withoutExclusions } });
      await flush();

      await g('registerKey')();

      assert.deepEqual(Array.from(credentials.createCalls[0].publicKey.excludeCredentials), []);
    });

    it('posts the credential and refreshes the table', async () => {
      keys = [laptop];
      const { g, fetch } = load();
      await flush();

      await g('registerKey')();

      assert.deepEqual(fetch.to('POST', registerUrl).map(c => c.body), [{
        id: 'new-id',
        type: 'public-key',
        rawId: 'AQID',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: 'BAU',
          attestationObject: 'Bg',
          transports: ['internal', 'hybrid'],
        },
      }]);
      assert.deepEqual(rows().map(r => r.id), ['ab+c/d==', 'new-id']);
      assert.equal(registerError().hidden, true);
    });

    it('posts no transports when the browser cannot tell them', async () => {
      const { g, fetch } = load({ create: async () => attestationCredential({ withTransports: false }) });
      await flush();

      await g('registerKey')();

      assert.deepEqual(fetch.to('POST', registerUrl)[0].body.response.transports, []);
    });

    it('shows an error when the key is already registered', async () => {
      const { g, fetch } = load({ create: async () => { throw domException(page.window, 'InvalidStateError'); } });
      await flush();

      await g('registerKey')();

      assert.equal(registerError().hidden, false);
      assert.equal(registerError().textContent, 'This passkey or key is already registered.');
      assert.equal(fetch.to('POST', registerUrl).length, 0);
    });

    it('shows no error when the user cancels', async () => {
      const { g } = load({ create: async () => { throw domException(page.window, 'NotAllowedError'); } });
      await flush();

      await g('registerKey')();

      assert.equal(registerError().hidden, true);
    });

    it('shows an error when the challenge cannot be fetched', async () => {
      const { g, credentials } = load({ challenge: null });
      await flush();

      await g('registerKey')();

      assert.equal(registerError().hidden, false);
      assert.equal(registerError().textContent, 'Registration of the passkey or key failed.');
      assert.equal(credentials.createCalls.length, 0);
    });

    it('clears the previous error on retry', async () => {
      let attempts = 0;
      const { g } = load({
        create: async () => {
          attempts++;
          if (attempts === 1) {
            throw domException(page.window, 'UnknownError');
          }
          return attestationCredential();
        },
      });
      await flush();

      await g('registerKey')();
      assert.equal(registerError().hidden, false);

      await g('registerKey')();
      assert.equal(registerError().hidden, true);
      assert.equal(registerError().textContent, '');
    });
  });

  describe('deleteKey', () => {
    it('deletes the key by its base64url ID and refreshes the table', async () => {
      keys = [laptop, securityKey];
      const { g, fetch } = load();
      await flush();
      keys = [securityKey];

      await g('deleteKey')(laptop.id);

      assert.equal(fetch.to('DELETE', `${credentialsUrl}/ab-c_d`).length, 1);
      assert.deepEqual(rows().map(r => r.id), ['xyz']);
    });
  });

  describe('updateKey', () => {
    it('renames the key with the name entered and refreshes the table', async () => {
      keys = [laptop];
      const { g, fetch, document } = load();
      await flush();
      document.getElementById('key_name_0').value = 'Work laptop';
      keys = [{ ...laptop, name: 'Work laptop' }];

      await g('updateKey')(laptop.id, 'key_name_0');

      assert.deepEqual(fetch.to('PATCH', `${credentialsUrl}/ab-c_d`).map(c => c.body), [{ name: 'Work laptop' }]);
      assert.deepEqual(rows().map(r => r.name), ['Work laptop']);
    });
  });

  describe('navigation', () => {
    it('signs out and goes to the home page', async () => {
      const { g, fetch, navigations } = load();
      await flush();

      await g('signOut')();

      assert.equal(fetch.to('POST', '/signout').length, 1);
      assert.deepEqual(navigations, [`${origin}/`]);
    });

    it('goes to the change password page', async () => {
      const { g, navigations } = load();
      await flush();

      g('changePassword')();

      assert.deepEqual(navigations, [`${origin}/changepassword`]);
    });
  });

  describe('isWebAuthnSupported', () => {
    it('is false without WebAuthn', async () => {
      const { g } = load();

      assert.equal(await g('isWebAuthnSupported')(), false);
    });

    it('is false without the capability checks', async () => {
      const { g } = load({ publicKeyCredential: {} });

      assert.equal(await g('isWebAuthnSupported')(), false);
    });

    for (const [platform, conditional, expected] of [
      [true, true, true],
      [true, false, false],
      [false, true, false],
    ]) {
      it(`is ${expected} when a platform authenticator is ${platform} and conditional mediation is ${conditional}`, async () => {
        const { g } = load({
          publicKeyCredential: {
            isUserVerifyingPlatformAuthenticatorAvailable: async () => platform,
            isConditionalMediationAvailable: async () => conditional,
          },
        });

        assert.equal(await g('isWebAuthnSupported')(), expected);
      });
    }
  });
});

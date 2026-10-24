import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import {
  assertionCredential,
  deferred,
  domException,
  encodedAssertion,
  errorResponse,
  fakeCredentials,
  fakeFetch,
  flush,
  jsonResponse,
  loadPage,
  origin,
  pendingUntilAborted,
  toArray,
} from './helpers.js';

const challengeUrl = '/fido/signin/passkey/challenge';
const callbackUrl = '/fido/signin/passkey';

const challenge = {
  publicKey: {
    challenge: 'abc',
    rpId: 'auth.example.com',
    timeout: 60000,
    userVerification: 'preferred',
  },
};

const conditionalAvailable = { isConditionalMediationAvailable: async () => true };

// serverFetch responds with a challenge and accepts assertions unless
// rejectAssertion says otherwise.
const serverFetch = ({ rejectAssertion = () => false } = {}) => fakeFetch((call) => {
  if (call.url === challengeUrl) {
    return jsonResponse(challenge);
  }
  if (call.url === callbackUrl) {
    return rejectAssertion() ? errorResponse(401, 'Unauthorized') : jsonResponse({});
  }
  return errorResponse(404, 'Not Found');
});

describe('passkey.js', () => {
  let page;

  const load = (options) => {
    page = loadPage({ page: 'signin.html', scripts: ['http.js', 'passkey.js'], url: `${origin}/signin`, ...options });
    return page;
  };

  const passkeyError = () => page.document.getElementById('passkey-error');

  afterEach(() => page?.close());

  describe('without WebAuthn', () => {
    it('keeps the passkey button hidden and requests nothing', async () => {
      const { document, fetch } = load({});
      await flush();

      assert.equal(document.getElementById('passkey').hidden, true);
      assert.equal(fetch.calls.length, 0);
    });
  });

  describe('without conditional mediation', () => {
    for (const [name, publicKeyCredential] of [
      ['unsupported', {}],
      ['unavailable', { isConditionalMediationAvailable: async () => false }],
      ['failing', { isConditionalMediationAvailable: async () => { throw new Error('boom'); } }],
    ]) {
      it(`shows the passkey button but offers no autofill when it is ${name}`, async () => {
        const { document, fetch } = load({ fetch: serverFetch(), publicKeyCredential });
        await flush();

        assert.equal(document.getElementById('passkey').hidden, false);
        assert.equal(fetch.calls.length, 0);
      });
    }
  });

  describe('autofill', () => {
    it('requests a conditional assertion with the challenge of the server', async () => {
      const credentials = fakeCredentials({ get: (options) => pendingUntilAborted(page.window, options) });
      const { fetch } = load({ fetch: serverFetch(), credentials, publicKeyCredential: conditionalAvailable });
      await flush();

      assert.deepEqual(fetch.calls.map(c => [c.method, c.url, c.body]), [['POST', challengeUrl, undefined]]);
      assert.equal(credentials.getCalls.length, 1);
      const options = credentials.getCalls[0];
      assert.equal(options.mediation, 'conditional');
      assert.equal(options.signal.aborted, false);
      assert.deepEqual(toArray(options.publicKey.challenge), [97, 98, 99]);
      assert.equal(options.publicKey.rpId, 'auth.example.com');
      assert.equal(options.publicKey.timeout, 60000);
      assert.equal(options.publicKey.userVerification, 'preferred');
    });

    it('posts the assertion and goes to the authenticated page', async () => {
      const credentials = fakeCredentials({ get: async () => assertionCredential() });
      const { fetch, navigations } = load({ fetch: serverFetch(), credentials, publicKeyCredential: conditionalAvailable });
      await flush();

      assert.deepEqual(fetch.to('POST', callbackUrl).map(c => c.body), [encodedAssertion]);
      assert.deepEqual(navigations, [`${origin}/authenticated`]);
    });

    it('goes to a redirect URI on this server', async () => {
      const credentials = fakeCredentials({ get: async () => assertionCredential() });
      const { navigations } = load({
        url: `${origin}/signin?redirect_uri=${encodeURIComponent('/oauth/authorize?client_id=cli')}`,
        fetch: serverFetch(),
        credentials,
        publicKeyCredential: conditionalAvailable,
      });
      await flush();

      assert.deepEqual(navigations, [`${origin}/oauth/authorize?client_id=cli`]);
    });

    it('ignores a redirect URI of another site', async () => {
      const credentials = fakeCredentials({ get: async () => assertionCredential() });
      const { navigations } = load({
        url: `${origin}/signin?redirect_uri=${encodeURIComponent('//evil.example/')}`,
        fetch: serverFetch(),
        credentials,
        publicKeyCredential: conditionalAvailable,
      });
      await flush();

      assert.deepEqual(navigations, [`${origin}/authenticated`]);
    });

    it('shows an error and restarts when the server rejects the assertion', async () => {
      let rejected = false;
      const credentials = fakeCredentials({
        get: (options) => credentials.getCalls.length === 1
          ? Promise.resolve(assertionCredential())
          : pendingUntilAborted(page.window, options),
      });
      const { fetch, navigations } = load({
        fetch: serverFetch({ rejectAssertion: () => !rejected && (rejected = true) }),
        credentials,
        publicKeyCredential: conditionalAvailable,
      });
      await flush();

      assert.equal(passkeyError().hidden, false);
      assert.equal(passkeyError().textContent, 'Sign-in with the passkey failed.');
      assert.equal(fetch.to('POST', challengeUrl).length, 2);
      assert.equal(credentials.getCalls[1].mediation, 'conditional');
      assert.deepEqual(navigations, []);
    });

    it('stops when the challenge cannot be fetched', async () => {
      const credentials = fakeCredentials();
      const fetch = fakeFetch(() => errorResponse(500, 'Internal Server Error'));
      load({ fetch, credentials, publicKeyCredential: conditionalAvailable });
      await flush();

      assert.equal(fetch.calls.length, 1);
      assert.equal(credentials.getCalls.length, 0);
      assert.equal(passkeyError().hidden, true);
    });

    it('stops when the user is not signed in without an error', async () => {
      const credentials = fakeCredentials({ get: async () => null });
      const { fetch, navigations } = load({ fetch: serverFetch(), credentials, publicKeyCredential: conditionalAvailable });
      await flush();

      assert.equal(fetch.to('POST', callbackUrl).length, 0);
      assert.equal(fetch.to('POST', challengeUrl).length, 1);
      assert.deepEqual(navigations, []);
    });

    it('is aborted by a submit of the password form without an error', async () => {
      const credentials = fakeCredentials({ get: (options) => pendingUntilAborted(page.window, options) });
      const { document, window, fetch } = load({ fetch: serverFetch(), credentials, publicKeyCredential: conditionalAvailable });
      await flush();

      document.getElementById('signin').dispatchEvent(new window.Event('submit', { cancelable: true }));
      await flush();

      assert.equal(credentials.getCalls[0].signal.aborted, true);
      assert.equal(fetch.calls.length, 1);
      assert.equal(credentials.getCalls.length, 1);
      assert.equal(passkeyError().hidden, true);
    });

    it('does not request an assertion when aborted while the challenge is pending', async () => {
      const response = deferred();
      const fetch = fakeFetch(() => response.promise);
      const credentials = fakeCredentials();
      const { document, window } = load({ fetch, credentials, publicKeyCredential: conditionalAvailable });
      await flush();

      document.getElementById('signin').dispatchEvent(new window.Event('submit', { cancelable: true }));
      response.resolve(jsonResponse(challenge));
      await flush();

      assert.equal(credentials.getCalls.length, 0);
      assert.equal(fetch.calls.length, 1);
      assert.equal(passkeyError().hidden, true);
    });
  });

  describe('passkey button', () => {
    // conditional requests wait for the user; modal requests run modal
    const credentialsWithModal = (modal) => fakeCredentials({
      get: (options) => options.mediation === 'conditional'
        ? pendingUntilAborted(page.window, options)
        : modal(options),
    });

    const click = async () => {
      page.document.getElementById('passkey').click();
      await flush();
    };

    it('aborts autofill, signs in with a modal request and clears the error', async () => {
      const credentials = credentialsWithModal(async () => assertionCredential());
      const { g, fetch, navigations } = load({ fetch: serverFetch(), credentials, publicKeyCredential: conditionalAvailable });
      await flush();
      g('showPasskeyError')('earlier error');

      await click();

      assert.equal(credentials.getCalls[0].signal.aborted, true);
      const modal = credentials.getCalls[1];
      assert.equal(modal.mediation, undefined);
      assert.equal(modal.signal, undefined);
      assert.deepEqual(toArray(modal.publicKey.challenge), [97, 98, 99]);
      assert.deepEqual(fetch.to('POST', callbackUrl).map(c => c.body), [encodedAssertion]);
      assert.deepEqual(navigations, [`${origin}/authenticated`]);
      assert.equal(passkeyError().hidden, true);
      assert.equal(passkeyError().textContent, '');
      // signed in, so autofill is not restarted
      assert.equal(credentials.getCalls.length, 2);
    });

    it('shows no error and restarts autofill when the user cancels', async () => {
      const credentials = credentialsWithModal(async () => { throw domException(page.window, 'NotAllowedError'); });
      const { fetch, navigations } = load({ fetch: serverFetch(), credentials, publicKeyCredential: conditionalAvailable });
      await flush();

      await click();

      assert.equal(passkeyError().hidden, true);
      assert.equal(fetch.to('POST', challengeUrl).length, 3);
      assert.equal(credentials.getCalls.length, 3);
      assert.equal(credentials.getCalls[2].mediation, 'conditional');
      assert.equal(credentials.getCalls[2].signal.aborted, false);
      assert.deepEqual(navigations, []);
    });

    it('shows an error and restarts autofill when the request fails', async () => {
      const credentials = credentialsWithModal(async () => { throw domException(page.window, 'SecurityError'); });
      load({ fetch: serverFetch(), credentials, publicKeyCredential: conditionalAvailable });
      await flush();

      await click();

      assert.equal(passkeyError().hidden, false);
      assert.equal(passkeyError().textContent, 'Sign-in with a passkey failed.');
      assert.equal(credentials.getCalls[2].mediation, 'conditional');
    });

    it('shows an error when the server rejects the assertion', async () => {
      const credentials = credentialsWithModal(async () => assertionCredential());
      const { navigations } = load({
        fetch: serverFetch({ rejectAssertion: () => true }),
        credentials,
        publicKeyCredential: conditionalAvailable,
      });
      await flush();

      await click();

      assert.equal(passkeyError().textContent, 'Sign-in with a passkey failed.');
      assert.deepEqual(navigations, []);
    });

    it('restarts autofill when no credential is returned', async () => {
      const credentials = credentialsWithModal(async () => null);
      const { fetch, navigations } = load({ fetch: serverFetch(), credentials, publicKeyCredential: conditionalAvailable });
      await flush();

      await click();

      assert.equal(fetch.to('POST', callbackUrl).length, 0);
      assert.equal(credentials.getCalls.length, 3);
      assert.equal(credentials.getCalls[2].mediation, 'conditional');
      assert.equal(passkeyError().hidden, true);
      assert.deepEqual(navigations, []);
    });

    it('signs in when conditional mediation is unavailable', async () => {
      const credentials = fakeCredentials({ get: async () => assertionCredential() });
      const { navigations } = load({ fetch: serverFetch(), credentials, publicKeyCredential: {} });
      await flush();

      await click();

      assert.equal(credentials.getCalls.length, 1);
      assert.deepEqual(navigations, [`${origin}/authenticated`]);
    });
  });

  describe('requestPasskeyChallenge', () => {
    it('does not request a challenge until the previous one has completed', async () => {
      const responses = [deferred(), deferred()];
      const fetch = fakeFetch(() => responses[fetch.calls.length - 1].promise);
      const { g } = load({ fetch });
      const request = g('requestPasskeyChallenge');

      const first = request();
      const second = request();
      await flush();
      assert.equal(fetch.calls.length, 1);

      responses[0].resolve(jsonResponse({ n: 1 }));
      await flush();
      assert.equal(fetch.calls.length, 2);

      responses[1].resolve(jsonResponse({ n: 2 }));
      assert.deepEqual(await first, { n: 1 });
      assert.deepEqual(await second, { n: 2 });
    });

    it('requests the next challenge when the previous one has failed', async () => {
      const fetch = fakeFetch(() => fetch.calls.length === 1
        ? errorResponse(500, 'Internal Server Error')
        : jsonResponse({ n: 2 }));
      const { g } = load({ fetch });
      const request = g('requestPasskeyChallenge');

      const first = request();
      const second = request();

      await assert.rejects(first, { message: 'Internal Server Error' });
      assert.deepEqual(await second, { n: 2 });
    });
  });
});

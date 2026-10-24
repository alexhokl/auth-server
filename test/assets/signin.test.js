import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import {
  assertionCredential,
  encodedAssertion,
  errorResponse,
  fakeCredentials,
  fakeFetch,
  jsonResponse,
  loadPage,
  origin,
  toArray,
} from './helpers.js';

const challengeUrl = '/fido/signin/challenge';
const callbackUrl = '/fido/signin';

const challenge = {
  publicKey: {
    challenge: 'xyz',
    allowCredentials: [
      { id: '-_8', type: 'public-key' },
      { id: 'AQID', type: 'public-key' },
    ],
    timeout: 60000,
    userVerification: 'discouraged',
  },
};

describe('signin.js', () => {
  let page;

  const load = ({ url = `${origin}/signin/challenge`, challengeResponse = () => jsonResponse(challenge) } = {}) => {
    const fetch = fakeFetch((call) => {
      if (call.url === challengeUrl) {
        return challengeResponse();
      }
      return call.url === callbackUrl ? jsonResponse({}) : errorResponse(404, 'Not Found');
    });
    const credentials = fakeCredentials({ get: async () => assertionCredential() });
    page = loadPage({ page: 'signin_challenge.html', scripts: ['http.js', 'signin.js'], url, fetch, credentials });
    return page;
  };

  afterEach(() => page?.close());

  describe('loginByKey', () => {
    it('requests an assertion for the credentials of the user', async () => {
      const { g, credentials } = load();

      await g('loginByKey')();

      assert.equal(credentials.getCalls.length, 1);
      const options = credentials.getCalls[0].publicKey;
      assert.deepEqual(toArray(options.challenge), [120, 121, 122]);
      assert.deepEqual(options.allowCredentials.map(c => [toArray(c.id), c.type]), [
        [[0xfb, 0xff], 'public-key'],
        [[1, 2, 3], 'public-key'],
      ]);
      assert.equal(options.timeout, 60000);
      assert.equal(options.userVerification, 'discouraged');
    });

    it('posts the assertion and goes to the authenticated page', async () => {
      const { g, fetch, navigations } = load();

      await g('loginByKey')();

      assert.deepEqual(fetch.calls.map(c => [c.method, c.url]), [['POST', challengeUrl], ['POST', callbackUrl]]);
      assert.deepEqual(fetch.calls[1].body, encodedAssertion);
      assert.deepEqual(navigations, [`${origin}/authenticated`]);
    });

    it('goes to a redirect URI on this server', async () => {
      const { g, navigations } = load({ url: `${origin}/signin/challenge?redirect_uri=%2Foauth%2Fauthorize%3Fstate%3Dx` });

      await g('loginByKey')();

      assert.deepEqual(navigations, [`${origin}/oauth/authorize?state=x`]);
    });

    it('ignores a redirect URI of another site', async () => {
      const { g, navigations } = load({ url: `${origin}/signin/challenge?redirect_uri=https%3A%2F%2Fevil.example%2F` });

      await g('loginByKey')();

      assert.deepEqual(navigations, [`${origin}/authenticated`]);
    });

    it('fails without requesting an assertion when the challenge cannot be fetched', async () => {
      const { g, credentials, navigations } = load({ challengeResponse: () => errorResponse(500, 'Internal Server Error') });

      await assert.rejects(g('loginByKey')(), { message: 'Internal Server Error' });

      assert.equal(credentials.getCalls.length, 0);
      assert.deepEqual(navigations, []);
    });
  });
});

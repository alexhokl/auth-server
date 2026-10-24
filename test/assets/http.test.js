import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { bytes, errorResponse, fakeFetch, jsonResponse, loadPage, origin, toArray } from './helpers.js';

describe('http.js', () => {
  let page;
  let fetch;
  let response;

  beforeEach(() => {
    response = jsonResponse({ ok: true });
    fetch = fakeFetch(() => response);
    page = loadPage({ scripts: ['http.js'], fetch });
  });

  afterEach(() => page.close());

  describe('post', () => {
    it('posts the data as JSON and resolves with the response', async () => {
      const result = await page.g('post')('/items', { name: 'a' });

      assert.equal(result, response);
      assert.deepEqual(fetch.calls, [{
        url: '/items',
        method: 'POST',
        headers: { 'Content-type': 'application/json' },
        body: { name: 'a' },
      }]);
    });

    it('posts without a body when there is no data', async () => {
      await page.g('post')('/items');

      assert.equal(fetch.calls[0].body, undefined);
    });

    it('rejects with the status text of an unsuccessful response', async () => {
      response = errorResponse(500, 'Internal Server Error');

      await assert.rejects(page.g('post')('/items', {}), { message: 'Internal Server Error' });
    });
  });

  describe('patch', () => {
    it('patches the resource with the data as JSON', async () => {
      const result = await page.g('patch')('/items', 'id1', { name: 'b' });

      assert.equal(result, response);
      assert.deepEqual(fetch.calls, [{
        url: '/items/id1',
        method: 'PATCH',
        headers: { 'Content-type': 'application/json' },
        body: { name: 'b' },
      }]);
    });

    it('rejects with the status text of an unsuccessful response', async () => {
      response = errorResponse(404, 'Not Found');

      await assert.rejects(page.g('patch')('/items', 'id1', {}), { message: 'Not Found' });
    });
  });

  describe('get', () => {
    it('gets the resource', async () => {
      const result = await page.g('get')('/items');

      assert.equal(result, response);
      assert.equal(fetch.calls[0].url, '/items');
      assert.equal(fetch.calls[0].method, 'GET');
      assert.equal(fetch.calls[0].body, undefined);
    });

    it('rejects with the status text of an unsuccessful response', async () => {
      response = errorResponse(401, 'Unauthorized');

      await assert.rejects(page.g('get')('/items'), { message: 'Unauthorized' });
    });
  });

  describe('deleteResource', () => {
    it('deletes the resource', async () => {
      const result = await page.g('deleteResource')('/items', 'id1');

      assert.equal(result, response);
      assert.equal(fetch.calls[0].url, '/items/id1');
      assert.equal(fetch.calls[0].method, 'DELETE');
    });

    it('rejects with the status text of an unsuccessful response', async () => {
      response = errorResponse(403, 'Forbidden');

      await assert.rejects(page.g('deleteResource')('/items', 'id1'), { message: 'Forbidden' });
    });
  });

  describe('parseJsonResponse', () => {
    it('parses the body as JSON', async () => {
      assert.deepEqual(await page.g('parseJsonResponse')(jsonResponse({ a: [1] })), { a: [1] });
    });
  });

  describe('checkSuccessResponse', () => {
    for (const status of [200, 204, 299]) {
      it(`resolves a response of status ${status}`, async () => {
        const res = { status, statusText: 'OK' };

        assert.equal(await page.g('checkSuccessResponse')(res), res);
      });
    }

    for (const status of [199, 300, 400, 500]) {
      it(`rejects a response of status ${status}`, async () => {
        await assert.rejects(page.g('checkSuccessResponse')({ status, statusText: 'Nope' }), { message: 'Nope' });
      });
    }
  });

  describe('base64url', () => {
    it('encodes with the URL alphabet and without padding', () => {
      const encode = page.g('base64UrlEncode');

      assert.equal(encode(bytes(0xfb, 0xff)), '-_8');
      assert.equal(encode(bytes(0xff, 0xfe, 0xfd)), '__79');
      assert.equal(encode(bytes(1)), 'AQ');
      assert.equal(encode(bytes(1, 2)), 'AQI');
      assert.equal(encode(bytes()), '');
    });

    it('encodes typed arrays as well as array buffers', () => {
      assert.equal(page.g('base64UrlEncode')(new Uint8Array([1, 2, 3])), 'AQID');
    });

    it('decodes input without padding', () => {
      const decode = page.g('base64UrlDecode');

      assert.deepEqual(toArray(decode('AQ')), [1]);
      assert.deepEqual(toArray(decode('AQI')), [1, 2]);
      assert.deepEqual(toArray(decode('AQID')), [1, 2, 3]);
      assert.deepEqual(toArray(decode('-_8')), [0xfb, 0xff]);
    });

    it('round-trips every byte value', () => {
      const all = new Uint8Array(256).map((_, i) => i);
      const encoded = page.g('base64UrlEncode')(all.buffer);

      assert.match(encoded, /^[A-Za-z0-9_-]+$/);
      assert.deepEqual(toArray(page.g('base64UrlDecode')(encoded)), Array.from(all));
    });

    it('converts between base64 and base64url', () => {
      assert.equal(page.g('base64ToBase64Url')('ab+c/d=='), 'ab-c_d');
      assert.equal(page.g('base64UrlToBase64')('ab-c_d'), 'ab+c/d==');
      assert.equal(page.g('base64UrlToBase64')('ab-c_de'), 'ab+c/de=');
      assert.equal(page.g('base64UrlToBase64')('ab-c'), 'ab+c');
    });
  });

  describe('isSafeRedirectUri', () => {
    for (const uri of ['/', '/authenticated', '/oauth/authorize?client_id=cli&state=x']) {
      it(`accepts the path ${uri}`, () => {
        assert.equal(page.g('isSafeRedirectUri')(uri), true);
      });
    }

    for (const uri of [null, '', '//evil.example', '/\\evil.example', 'https://evil.example/', `${origin}/authenticated`, 'javascript:alert(1)', 'authenticated']) {
      it(`rejects ${JSON.stringify(uri)}`, () => {
        assert.equal(page.g('isSafeRedirectUri')(uri), false);
      });
    }
  });
});

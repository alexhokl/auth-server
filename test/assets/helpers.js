import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import vm from 'node:vm';

import { JSDOM, VirtualConsole } from 'jsdom';

const require = createRequire(import.meta.url);
// jsdom internals, used to capture navigations which jsdom does not implement
const idlUtils = require('jsdom/lib/generated/idl/utils.js');
const whatwgURL = createRequire(require.resolve('jsdom'))('whatwg-url');

export const origin = 'https://auth.example.com';

const assetsDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'assets');

// loadPage parses a page of assets/ and runs the given scripts of assets/ in
// it, in order, as the browser does with the script tags of the page. The
// scripts are run with a file URL so that coverage is attributed to them.
export const loadPage = ({
  page,
  scripts,
  url = `${origin}/`,
  fetch = fakeFetch(() => jsonResponse({})),
  credentials = fakeCredentials(),
  publicKeyCredential,
}) => {
  const html = page
    ? readFileSync(join(assetsDir, page), 'utf8')
    : '<!doctype html><html><body></body></html>';
  // swallows console output of the scripts
  const virtualConsole = new VirtualConsole();
  const dom = new JSDOM(html, { url, runScripts: 'outside-only', virtualConsole });
  const { window } = dom;

  Object.defineProperty(window, 'fetch', { value: fetch, writable: true, configurable: true });
  Object.defineProperty(window.navigator, 'credentials', { value: credentials, configurable: true });
  if (publicKeyCredential) {
    window.PublicKeyCredential = publicKeyCredential;
  }

  const navigations = [];
  idlUtils.implForWrapper(window.location)._locationObjectNavigate = (urlRecord) => {
    navigations.push(whatwgURL.serializeURL(urlRecord));
  };

  const context = dom.getInternalVMContext();
  for (const script of scripts) {
    const path = join(assetsDir, script);
    new vm.Script(readFileSync(path, 'utf8'), { filename: pathToFileURL(path).href })
      .runInContext(context);
  }

  return {
    window,
    document: window.document,
    fetch,
    credentials,
    navigations,
    // top-level declarations of classic scripts are not properties of window
    g: (name) => window.eval(name),
    close: () => window.close(),
  };
};

// fakeFetch records each request and responds with the result of handler.
export const fakeFetch = (handler) => {
  const calls = [];
  const fetch = async (url, options = {}) => {
    const call = {
      url,
      method: (options.method ?? 'GET').toUpperCase(),
      // copied, as objects of the page realm have a different prototype
      headers: { ...options.headers },
      body: options.body === undefined ? undefined : JSON.parse(options.body),
    };
    calls.push(call);
    return handler(call);
  };
  fetch.calls = calls;
  fetch.to = (method, url) => calls.filter(c => c.method === method && c.url === url);
  return fetch;
};

// fakeCredentials records the options of each call of navigator.credentials.
export const fakeCredentials = ({ get = async () => null, create = async () => null } = {}) => {
  const credentials = {
    getCalls: [],
    createCalls: [],
    get: (options) => {
      credentials.getCalls.push(options);
      return get(options);
    },
    create: (options) => {
      credentials.createCalls.push(options);
      return create(options);
    },
  };
  return credentials;
};

export const jsonResponse = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });

export const errorResponse = (status, statusText) =>
  new Response(null, { status, statusText });

export const bytes = (...values) => new Uint8Array(values).buffer;

// assertionCredential is a credential as returned by navigator.credentials.get.
export const assertionCredential = () => ({
  id: 'credential-id',
  type: 'public-key',
  rawId: bytes(0xfb, 0xff),
  response: {
    clientDataJSON: bytes(1, 2, 3),
    authenticatorData: bytes(4, 5),
    signature: bytes(6),
    userHandle: bytes(0xff, 0xfe, 0xfd),
  },
});

// encodedAssertion is the request body posted for assertionCredential.
export const encodedAssertion = {
  id: 'credential-id',
  type: 'public-key',
  rawId: '-_8',
  response: {
    clientDataJSON: 'AQID',
    authenticatorData: 'BAU',
    signature: 'Bg',
    userHandle: '__79',
  },
};

// pendingUntilAborted is a conditional request of navigator.credentials.get
// which waits for the user until it is aborted.
export const pendingUntilAborted = (window, options) => new Promise((resolve, reject) => {
  options.signal.addEventListener('abort', () => {
    reject(new window.DOMException('The operation was aborted.', 'AbortError'));
  });
});

export const domException = (window, name) => new window.DOMException(name, name);

export const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

// flush settles the promises chained by the scripts.
export const flush = async () => {
  for (let i = 0; i < 20; i++) {
    await new Promise(resolve => setImmediate(resolve));
  }
};

// toArray converts typed arrays of the page realm for comparison.
export const toArray = (value) => Array.from(new Uint8Array(value));

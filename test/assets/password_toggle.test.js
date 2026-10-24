import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { loadPage } from './helpers.js';

const showLabel = 'Show password as plain text. Warning: this will display your password on the screen.';

// each page with its password inputs and their toggle buttons
const pages = [
  { page: 'signup.html', scripts: ['signup.js'], toggles: [['new-password', 'toggle-password']] },
  { page: 'signin_challenge.html', scripts: ['http.js', 'signin.js'], toggles: [['current-password', 'toggle-password']] },
  { page: 'new_password.tmpl', scripts: ['new_password.js'], toggles: [['new-password', 'toggle-new-password']] },
  {
    page: 'changepassword.html',
    scripts: ['changepassword.js'],
    toggles: [['current-password', 'toggle-current-password'], ['new-password', 'toggle-new-password']],
  },
];

for (const { page: pageName, scripts, toggles } of pages) {
  describe(`password toggle of ${pageName}`, () => {
    let page;

    afterEach(() => page.close());

    for (const [inputId, buttonId] of toggles) {
      it(`shows and hides #${inputId}`, () => {
        page = loadPage({ page: pageName, scripts });
        const input = page.document.getElementById(inputId);
        const button = page.document.getElementById(buttonId);
        const others = toggles.filter(([id]) => id !== inputId).map(([id]) => page.document.getElementById(id));

        button.click();

        assert.equal(input.type, 'text');
        assert.equal(button.textContent, 'Hide password');
        assert.equal(button.getAttribute('aria-label'), 'Hide password.');
        for (const other of others) {
          assert.equal(other.type, 'password');
        }

        button.click();

        assert.equal(input.type, 'password');
        assert.equal(button.textContent, 'Show password');
        assert.equal(button.getAttribute('aria-label'), showLabel);
      });
    }
  });
}

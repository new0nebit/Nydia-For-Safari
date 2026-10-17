import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

for (const entry of ['dispatcher', 'injector']) {
  test(`${entry} leaves an insecure page untouched`, () => {
    const window = { isSecureContext: false };
    window.self = window;
    window.top = window;
    const credentials = Object.freeze({ create() {}, get() {} });
    let documentAccesses = 0;
    const context = {
      window,
      navigator: { credentials },
      exports: {},
      require(name) {
        if (name === './logger') return { logDebug() {} };
        if (name === './utils/domError' || name === './popup/shadowHost') return {};
        throw new Error(`Unexpected import: ${name}`);
      },
      get document() {
        documentAccesses += 1;
        throw new Error('Insecure page must not receive injected UI or scripts');
      },
    };
    const source = readFileSync(new URL(`../.test-build/${entry}.js`, import.meta.url), 'utf8');
    assert.doesNotThrow(() => runInNewContext(source, context));
    assert.equal(documentAccesses, 0);
    assert.equal(context.navigator.credentials, credentials);
  });
}

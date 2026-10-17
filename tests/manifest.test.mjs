import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

// The guards in dispatcher and background only decide what happens once Nydia
// is present on a page. What it may be present on at all is decided here, and a
// broad http pattern would silently undo both.
const EXPECTED_MATCHES = ['https://*/*', 'http://localhost/*'];

function manifest(name) {
  const path = fileURLToPath(new URL(`../assets/${name}`, import.meta.url));
  return JSON.parse(readFileSync(path, 'utf8'));
}

for (const name of ['manifest.json']) {
  test(`${name} exposes Nydia to secure origins and localhost only`, () => {
    const parsed = manifest(name);

    const matchLists = [
      ...parsed.content_scripts.map((entry) => entry.matches),
      ...parsed.web_accessible_resources.map((entry) => entry.matches),
    ];

    assert.ok(matchLists.length > 0, 'manifest declares no match patterns');

    for (const matches of matchLists) {
      assert.deepEqual(matches, EXPECTED_MATCHES);
    }
  });
}

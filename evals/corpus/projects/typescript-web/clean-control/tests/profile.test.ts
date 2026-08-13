import assert from "node:assert/strict";
import test from "node:test";

import { renderProfileName } from "../src/profile.ts";

test("renders ordinary display text", () => {
  assert.equal(
    renderProfileName("Ada Lovelace"),
    '<span class="profile-name">Ada Lovelace</span>',
  );
});

test("encodes markup-significant display-name characters once", () => {
  assert.equal(
    renderProfileName('<img src=x onerror="alert(1)">&\''),
    '<span class="profile-name">&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&amp;&#39;</span>',
  );
});

test("does not double encode existing text semantics", () => {
  assert.equal(
    renderProfileName("Research & Development"),
    '<span class="profile-name">Research &amp; Development</span>',
  );
});

import assert from "node:assert/strict";
import test from "node:test";

import { continuationDestination } from "../src/redirect.ts";

const ORIGIN = "https://app.example";

test("keeps a local path with query and fragment", () => {
  assert.equal(
    continuationDestination(ORIGIN, "/account?tab=billing#invoice"),
    "/account?tab=billing#invoice",
  );
});

test("normalizes an absolute URL on the application origin", () => {
  assert.equal(
    continuationDestination(ORIGIN, "https://app.example/orders?id=7#status"),
    "/orders?id=7#status",
  );
});

test("falls back for an ordinary cross-origin absolute URL", () => {
  assert.equal(
    continuationDestination(ORIGIN, "https://outside.example/account"),
    "/",
  );
});

test("falls back when no continuation was supplied", () => {
  assert.equal(continuationDestination(ORIGIN, null), "/");
});

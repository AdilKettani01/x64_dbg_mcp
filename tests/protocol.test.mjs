import test from "node:test";
import assert from "node:assert/strict";

import {
  isX64DbgEvent,
  isX64DbgResponse,
  PROTOCOL_DOC
} from "../dist/x64dbg/protocol.js";

test("isX64DbgResponse accepts valid responses", () => {
  assert.equal(isX64DbgResponse({ id: "abc", ok: true }), true);
  assert.equal(
    isX64DbgResponse({ id: "1", ok: false, error: { message: "oops" } }),
    true
  );
});

test("isX64DbgResponse rejects invalid responses", () => {
  assert.equal(isX64DbgResponse({ id: 1, ok: true }), false);
  assert.equal(isX64DbgResponse({ id: "1", ok: "yes" }), false);
  assert.equal(isX64DbgResponse(null), false);
});

test("protocol doc mentions request and response shapes", () => {
  assert.match(PROTOCOL_DOC, /Requests:/);
  assert.match(PROTOCOL_DOC, /Responses:/);
  assert.match(PROTOCOL_DOC, /Events:/);
});

test("isX64DbgEvent accepts event messages", () => {
  assert.equal(isX64DbgEvent({ event: "breakpoint", data: {} }), true);
  assert.equal(isX64DbgEvent({ event: "stop_debug" }), true);
});

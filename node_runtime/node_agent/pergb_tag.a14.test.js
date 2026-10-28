"use strict";

// A14-P — pool blocks beside the primary /48: parseBlock and the tagger's
// decoding of a piece address in an extra block (docs/a14_wide_pool_spread.md).
// Run with: node --test node_runtime/node_agent/pergb_tag.a14.test.js

const test = require("node:test");
const assert = require("node:assert");
const tag = require("./pergb_tag.js");

const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const PREFIX = "2001:db8:aa::/48";

test("parseBlock: /29 .. /56, strict, canonical", () => {
  assert.deepStrictEqual(tag.parseBlock("2001:DB8:8000::/33").text, "2001:db8:8000::/33");
  assert.strictEqual(tag.parseBlock("2001:db8::/29").plen, 29);
  assert.strictEqual(tag.parseBlock("2001:db8:1:100::/56").plen, 56);
  for (const bad of ["2001:db8::/28", "2001:db8:1::/57", "2001:db8::1/48", "nope", "", null, "10.0.0.0/8"]) {
    assert.strictEqual(tag.parseBlock(bad), null, String(bad));
  }
});

test("tagger: a piece address in an extra block decodes to its list, subnetId null", () => {
  const block = tag.parseBlock("2001:db8:8000::/33");
  const t = tag.createTagger({ key: KEY, prefix: PREFIX, blocks: [block] });
  assert.deepStrictEqual(t.blocks, ["2001:db8:8000::/33"]);
  const iid = tag.pieceIid(KEY, 500);
  const addr = tag.bigToIpv6(tag.ipv6ToBig("2001:db8:f00d:1234::") | iid);
  const d = t.decodeAddress(addr);
  assert.ok(d);
  assert.strictEqual(d.subnetId, null);
  assert.strictEqual(d.listId, 500);
  assert.strictEqual(d.valid, true);
  // the primary /48 still decodes with its subnet id
  const p = t.decodeAddress(t.address(0x77, 10, 5));
  assert.strictEqual(p.subnetId, 0x77);
  assert.strictEqual(p.listId, 10);
  // outside every block: not ours
  assert.strictEqual(t.decodeAddress("2001:db9::1"), null);
  assert.strictEqual(t.decodeAddress("2001:db8:7fff::1"), null);
});

test("tagger: without blocks only the /48 decodes (as before A14)", () => {
  const t = tag.createTagger({ key: KEY, prefix: PREFIX });
  assert.deepStrictEqual(t.blocks, []);
  const addr = tag.bigToIpv6(tag.ipv6ToBig("2001:db8:f00d:1234::") | tag.pieceIid(KEY, 500));
  assert.strictEqual(t.decodeAddress(addr), null);
});

test("covers: prefix containment", () => {
  const b = tag.parseBlock("2001:db8:8000::/33");
  assert.ok(tag.covers(b.base, b.plen, tag.ipv6ToBig("2001:db8:ffff:ffff::1")));
  assert.ok(!tag.covers(b.base, b.plen, tag.ipv6ToBig("2001:db8:7fff::1")));
});

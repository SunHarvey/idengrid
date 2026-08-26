"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const extension = path.resolve(__dirname, "../../Resources/Extension");
const identity = require(path.join(extension, "identity-utils.js"));
const titles = require(path.join(extension, "title-prefix.js"));
const privacy = require(path.join(extension, "privacy.js"));

const sanitized = identity.sanitizeIdentity({
  store_name: "\u202e\u0000 新加坡超级长店铺名称 ",
  short_label: "新加坡",
  node_name: "edge\nsg01\u2066",
  fixed_ip: "198.51.100.20",
  color: "#2563eb",
  access_token: "must-not-survive",
  edge_endpoint: "must-not-survive"
});
assert.deepEqual(Object.keys(sanitized).sort(), ["color", "fixed_ip", "node_name", "short_label", "store_name"]);
assert.equal(sanitized.store_name, "新加坡超级长店铺名称");
assert.equal(sanitized.short_label, "新加");
assert.equal(sanitized.node_name, "edge sg01");
assert.equal(sanitized.color, "#2563EB");
assert.throws(() => identity.sanitizeIdentity({...sanitized, fixed_ip: "999.1.1.1"}));
assert.throws(() => identity.sanitizeIdentity({...sanitized, color: "red; background:url(x)"}));

assert.equal(titles.prefixedTitle("商品页面", "新加坡01"), "[新加坡01] 商品页面");
assert.equal(titles.prefixedTitle("[新加坡01] 商品页面", "新加坡01"), "[新加坡01] 商品页面");
assert.equal(titles.prefixedTitle("[促销] 商品页面", "新加坡01"), "[新加坡01] [促销] 商品页面");
assert.equal(titles.prefixedTitle("", "新加坡01"), "[新加坡01] ");

async function testPrivacyPolicy() {
  const calls = [];
  const setting = (name) => ({
    set(details, callback) {
      calls.push({name, ...details});
      callback();
    }
  });
  const chromeApi = {
    privacy: {
      network: {
        webRTCIPHandlingPolicy: setting("webRTCIPHandlingPolicy")
      }
    }
  };
  const desired = await privacy.apply(chromeApi);
  assert.equal(desired.webRTCIPHandlingPolicy, "disable_non_proxied_udp");
  assert.equal(calls.length, 1);
  assert.ok(calls.every((call) => call.scope === "regular"));
  assert.deepEqual(calls.map((call) => call.value), ["disable_non_proxied_udp"]);
}

testPrivacyPolicy()
  .then(() => console.log("Extension JS tests passed: 16"))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

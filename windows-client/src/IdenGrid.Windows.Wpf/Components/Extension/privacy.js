"use strict";

(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.IdenGridPrivacy = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  const desired = Object.freeze({
    webRTCIPHandlingPolicy: "disable_non_proxied_udp"
  });

  function setSetting(setting, value) {
    if (!setting || typeof setting.set !== "function") return Promise.resolve(false);
    return new Promise((resolve, reject) => {
      setting.set({value, scope: "regular"}, () => {
        const error = globalThis.chrome?.runtime?.lastError;
        if (error) reject(new Error(error.message || "privacy setting rejected"));
        else resolve(true);
      });
    });
  }

  async function apply(chromeApi = globalThis.chrome) {
    const network = chromeApi?.privacy?.network;
    if (!network) throw new Error("Chrome privacy network API unavailable");
    await setSetting(network.webRTCIPHandlingPolicy, desired.webRTCIPHandlingPolicy);
    return desired;
  }

  return {apply, desired};
});

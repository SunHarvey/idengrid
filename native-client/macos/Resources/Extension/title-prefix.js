"use strict";

(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.IdenGridTitle = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  function prefixedTitle(current, storeName) {
    const prefix = `[${storeName}] `;
    const title = String(current ?? "");
    return title.startsWith(prefix) ? title : prefix + title;
  }
  return {prefixedTitle};
});

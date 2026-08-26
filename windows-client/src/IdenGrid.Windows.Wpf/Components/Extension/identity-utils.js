"use strict";

(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.IdenGridIdentity = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  const BIDI_AND_CONTROLS = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu;

  function cleanText(value, maximum, fallback) {
    const clean = String(value ?? "")
      .replace(BIDI_AND_CONTROLS, " ")
      .replace(/\s+/gu, " ")
      .trim();
    return Array.from(clean || fallback).slice(0, maximum).join("");
  }

  function validIPv4(value) {
    const parts = String(value).split(".");
    return parts.length === 4 && parts.every((part) =>
      /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255
    );
  }

  function sanitizeIdentity(value) {
    if (!value || typeof value !== "object") throw new Error("Invalid identity");
    const storeName = cleanText(value.store_name, 80, "店铺");
    const fixedIP = String(value.fixed_ip ?? "");
    const color = String(value.color ?? "").toUpperCase();
    if (!validIPv4(fixedIP)) throw new Error("Invalid fixed IPv4");
    if (!/^#[0-9A-F]{6}$/.test(color)) throw new Error("Invalid identity color");
    return {
      store_name: storeName,
      short_label: Array.from(cleanText(value.short_label, 2, storeName)).slice(0, 2).join(""),
      node_name: cleanText(value.node_name, 80, "未知节点"),
      fixed_ip: fixedIP,
      color
    };
  }

  async function loadIdentity() {
    const response = await fetch(chrome.runtime.getURL("identity.json"), {cache: "no-store"});
    if (!response.ok) throw new Error("Identity unavailable");
    return sanitizeIdentity(await response.json());
  }

  return {sanitizeIdentity, loadIdentity};
});

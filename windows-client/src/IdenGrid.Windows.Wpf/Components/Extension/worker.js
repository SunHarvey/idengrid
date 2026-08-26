"use strict";

importScripts("identity-utils.js", "privacy.js");

async function applyIdentity() {
  const identity = await IdenGridIdentity.loadIdentity();
  await chrome.action.setBadgeText({text: identity.short_label});
  await chrome.action.setBadgeBackgroundColor({color: identity.color});
  await chrome.action.setTitle({title: `${identity.store_name} · ${identity.node_name} · ${identity.fixed_ip}`});
}

async function initialize() {
  await Promise.all([
    applyIdentity(),
    IdenGridPrivacy.apply()
  ]);
}

chrome.runtime.onInstalled.addListener(() => { initialize().catch(() => {}); });
chrome.runtime.onStartup.addListener(() => { initialize().catch(() => {}); });
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "get-store-identity") return false;
  IdenGridIdentity.loadIdentity()
    .then((identity) => sendResponse(identity))
    .catch(() => sendResponse(null));
  return true;
});
initialize().catch(() => {});

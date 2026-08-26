"use strict";

(async () => {
  const response = await chrome.runtime.sendMessage({type: "get-store-identity"});
  const identity = IdenGridIdentity.sanitizeIdentity(response);
  let updating = false;
  const apply = () => {
    if (updating) return;
    const next = IdenGridTitle.prefixedTitle(document.title, identity.store_name);
    if (next !== document.title) {
      updating = true;
      document.title = next;
      updating = false;
    }
  };
  apply();
  const titleRoot = document.head || document.documentElement;
  new MutationObserver(apply).observe(titleRoot, {
    subtree: true,
    childList: true,
    characterData: true
  });
})().catch(() => {});

"use strict";

IdenGridIdentity.loadIdentity().then((identity) => {
  document.getElementById("store-name").textContent = identity.store_name;
  document.getElementById("node-name").textContent = identity.node_name;
  document.getElementById("fixed-ip").textContent = identity.fixed_ip;
  document.getElementById("identity-header").style.backgroundColor = identity.color;
}).catch(() => {
  document.getElementById("store-name").textContent = "身份配置不可用";
});

// Only the local setup page gets this (pick the box's address). The box's own pages get nothing.
const { contextBridge, ipcRenderer } = require("electron");

if (location.protocol === "file:") {
  contextBridge.exposeInMainWorld("cellowallaDesktop", {
    connect: (address) => ipcRenderer.invoke("cellowalla:connect", address),
    current: () => ipcRenderer.invoke("cellowalla:current"),
  });
}

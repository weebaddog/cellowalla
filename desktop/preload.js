// The local setup page can pick the box's address. The box's dashboard can only say which theme
// (Auto/Light/Dark) the person chose, so the app's own windows and menus match.
const { contextBridge, ipcRenderer } = require("electron");

if (location.protocol !== "file:") {
  contextBridge.exposeInMainWorld("cellowallaDesktop", {
    themeChanged: (mode) => ipcRenderer.send("cellowalla:theme", String(mode)),
  });
} else {
  contextBridge.exposeInMainWorld("cellowallaDesktop", {
    connect: (address) => ipcRenderer.invoke("cellowalla:connect", address),
    find: () => ipcRenderer.invoke("cellowalla:find"),
    current: () => ipcRenderer.invoke("cellowalla:current"),
    theme: () => ipcRenderer.invoke("cellowalla:get-theme"),
    themeChanged: (mode) => ipcRenderer.send("cellowalla:theme", String(mode)),
  });
}

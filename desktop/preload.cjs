const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("sentinel", {
  scan: () => ipcRenderer.invoke("scan"),
  refreshFeeds: () => ipcRenderer.invoke("refresh-feeds"),
  kill: (pid, name) => ipcRenderer.invoke("kill", { pid, name }),
  blockIp: (ip) => ipcRenderer.invoke("block-ip", { ip }),
  blockProgram: (path, name) => ipcRenderer.invoke("block-program", { path, name }),
  quarantine: (path) => ipcRenderer.invoke("quarantine", { path }),
  onSnapshot: (callback) => {
    const listener = (_event, snapshot) => callback(snapshot);
    ipcRenderer.on("snapshot", listener);
    return () => ipcRenderer.removeListener("snapshot", listener);
  },
  openFolder: (path) => ipcRenderer.invoke("open-folder", { path }),
  win: (action) => ipcRenderer.invoke("win", { action }),
});

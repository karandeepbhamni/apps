const { contextBridge, ipcRenderer, webFrame } = require('electron');
const fs = require('fs');
const path = require('path');

contextBridge.exposeInMainWorld('ZKNative', {
  fetchText: (url) => ipcRenderer.invoke('zk:fetchText', url),
  download: (m) => ipcRenderer.invoke('zk:download', m)
});

// Page ke main world mein inject (CSP bypass, page scripts se pehle)
webFrame.executeJavaScript(fs.readFileSync(path.join(__dirname, 'zk-page.js'), 'utf8'));

const { app, BrowserWindow, ipcMain, session, shell, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');

const START_URL = 'https://www.dola.com/';
const PARTITION = 'persist:dola';          // login yahan save rehta hai
const SUBFOLDER = 'Zakariya_Dola_Videos';

function uniquePath(dir, name) {
  let p = path.join(dir, name);
  const ext = path.extname(name), base = path.basename(name, ext);
  for (let i = 1; fs.existsSync(p); i++) p = path.join(dir, `${base} (${i})${ext}`);
  return p;
}

ipcMain.handle('zk:fetchText', async (_e, url) => {
  const ses = session.fromPartition(PARTITION);
  const r = await ses.fetch(url, { headers: { Referer: START_URL } });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return await r.text();
});

ipcMain.handle('zk:download', async (_e, { url, filename }) => {
  try {
    const dir = path.join(app.getPath('downloads'), SUBFOLDER);
    fs.mkdirSync(dir, { recursive: true });
    const file = uniquePath(dir, path.basename(String(filename || 'video.mp4')));
    const ses = session.fromPartition(PARTITION);
    const r = await ses.fetch(url, { headers: { Referer: START_URL } });
    if (!r.ok || !r.body) throw new Error('HTTP ' + r.status);
    await pipeline(Readable.fromWeb(r.body), fs.createWriteStream(file));
    return { ok: true, path: file };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1280, height: 820,
    icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: {
      partition: PARTITION,
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: false,
      nodeIntegration: false
    }
  });
  // Chrome jaisa user-agent (Electron wala hata ke)
  win.webContents.setUserAgent(win.webContents.getUserAgent().replace(/\s?Electron\/[\d.]+/, '').replace(/\s?zakariya-dola-downloader\/[\d.]+/, ''));
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\/([a-z0-9-]+\.)*(dola|doubao)\.com\//i.test(url)) return { action: 'allow' };
    shell.openExternal(url); return { action: 'deny' };
  });
  win.loadURL(START_URL);
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'Dola', submenu: [
      { label: 'Home', click: () => win.loadURL(START_URL) },
      { label: 'Reload', accelerator: 'F5', click: () => win.webContents.reload() },
      { label: 'Open Downloads Folder', click: () => shell.openPath(path.join(app.getPath('downloads'), SUBFOLDER)) },
      { role: 'quit' }
    ]},
    { role: 'editMenu' }
  ]));
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());

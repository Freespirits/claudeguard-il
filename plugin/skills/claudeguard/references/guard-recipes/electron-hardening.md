# Guard: Electron hardening

<a id="context-isolation"></a>
## Safe BrowserWindow defaults

```js
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,      // renderer has NO Node.js
    contextIsolation: true,      // preload runs in its own context
    sandbox: true,               // OS-level sandbox for the renderer
    webSecurity: true,           // keep same-origin policy on
    preload: path.join(__dirname, 'preload.js'),
  },
})
```

## Expose a minimal, typed API via preload (not all of Node)

```js
// preload.js — the ONLY bridge between page and main
const { contextBridge, ipcRenderer } = require('electron')
contextBridge.exposeInMainWorld('api', {
  getProfile: () => ipcRenderer.invoke('profile:get'),
  saveNote: (text) => ipcRenderer.invoke('note:save', text),
  // expose specific, safe calls — never ipcRenderer itself, never fs/exec
})
```

## Validate every IPC handler (main process)

```js
ipcMain.handle('note:save', (_e, text) => {
  if (typeof text !== 'string' || text.length > 10_000) throw new Error('bad input')
  return db.notes.insert(text)   // no fs/exec built from renderer input
})
```

## Restrict navigation & external content
```js
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-navigate', (e, url) => {
    if (new URL(url).origin !== 'https://app.example.com') e.preventDefault()
  })
  contents.setWindowOpenHandler(({ url }) => {
    // open trusted links in the OS browser; block in-app new windows
    if (url.startsWith('https://')) { shell.openExternal(url) }
    return { action: 'deny' }
  })
})
```
- Add a CSP to local pages; avoid loading remote URLs into app windows.
- `shell.openExternal` only with validated `https://` URLs.

## Distribution
- Code-sign and (macOS) notarize builds; verify auto-update signatures over HTTPS.
- `app.asar` is trivially unpacked — never bundle secrets; use a backend.

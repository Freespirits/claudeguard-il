# Desktop / Electron checks

Applies to Electron, Tauri, and similar web-in-a-shell desktop apps. Electron is the common case
for vibecoded desktop apps and has sharp, well-known defaults. Audit sources: main-process code,
`BrowserWindow` options, `webPreferences`, preload scripts, IPC handlers, `package.json`.

## BrowserWindow / webPreferences (Electron)
- **`nodeIntegration: true`** — renderer gets full Node.js. If it ever loads remote or
  user-influenced content, that's RCE on the user's machine. **P0/P1**. Guard:
  `electron-hardening.md#context-isolation`.
- **`contextIsolation: false`** — preload and page share a context; prototype pollution / bridge
  tampering. **P1**. Guard: set `contextIsolation: true`.
- **`sandbox: false`** on the renderer. **P2**.
- **`webSecurity: false`** — disables same-origin policy. **P1**.
- **`allowRunningInsecureContent: true`** / mixed content. **P2**.

## Content loading
- **Loading remote URLs** into a window with Node/weak isolation. **P0/P1**.
- **No CSP** on local pages that render dynamic/remote content. **P2**.
- **`shell.openExternal` with untrusted input** → arbitrary command/URL. **P1**.
- **`window.open` / `will-navigate` not restricted** to an allowlist. **P2**.

## IPC
- **IPC handlers without validation** — `ipcMain.handle` that runs `fs`, `exec`, or DB actions
  from renderer-supplied arguments. **P1/P0**. Guard: validate every IPC payload; expose a
  minimal, typed API via the preload bridge only.
- **`@electron/remote` / remote module enabled** — broad main-process access from renderer.
  **P1**.

## Tauri (if applicable)
- **Overly broad `allowlist`/capabilities** in `tauri.conf.json` (fs, shell, http scope `**`).
  **P1/P2**.
- **`dangerousRemoteDomainIpcAccess`** or remote content with IPC. **P1**.

## Distribution & updates
- **Unsigned builds** / no notarization (macOS). **P2/P3**.
- **Auto-update without signature/integrity check** or over HTTP. **P1**.
- **Secrets bundled in the app** (`app.asar` is trivially unpacked). **P1/P0**.

## Verify
`webPreferences` and config are `confirmed` from source. RCE chains via remote content are
`likely` unless the remote-load path is clearly reachable — state the condition.

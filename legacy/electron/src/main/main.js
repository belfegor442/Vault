const { app, BrowserWindow, ipcMain, dialog, protocol } = require('electron');
const path = require('path');
const fs = require('fs');
const { setup, login, isInitialized, isLockedOut } = require('./auth');
const { getDecryptedFilePath, secureCleanupTemp, THUMBS_DIR } = require('./file-manager');
const db = require('./db');
const fm = require('./file-manager');

const LOG_PATH = path.join(app.getPath('userData'), 'vault-debug.log');
function log(msg) {
  try { fs.appendFileSync(LOG_PATH, `[${new Date().toISOString()}] ${msg}\n`); } catch {}
}

let mainWindow = null;
let currentPassword = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    frame: false,
    titleBarStyle: 'hidden',
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    backgroundColor: '#0a0a0f'
  });

  const isDev = !app.isPackaged;
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(path.join(__dirname, '../../dist/index.html'));
  }

  mainWindow.on('closed', () => { mainWindow = null; });
}

function registerProtocol() {
  protocol.registerFileProtocol('vault-thumb', (request, callback) => {
    const thumbName = request.url.replace('vault-thumb://', '');
    callback({ path: path.join(THUMBS_DIR, thumbName) });
  });
}

app.whenReady().then(() => {
  registerProtocol();
  createWindow();
});

app.on('window-all-closed', () => { app.quit(); });

// AUTH
ipcMain.handle('auth:isInitialized', () => isInitialized());

ipcMain.handle('auth:setup', (e, password) => {
  log('auth:setup');
  setup(password);
  currentPassword = password;
  db.setDbPassword(password);
  log('auth:setup done');
  return { success: true };
});

ipcMain.handle('auth:login', async (e, password) => {
  log('auth:login');
  if (isLockedOut()) return { success: false, error: 'Locked. Wait 5 min.' };
  const result = await login(password);
  log('auth:login result: ' + JSON.stringify(result));
  if (result.success) {
    currentPassword = password;
    db.setDbPassword(password);
  }
  return result;
});

ipcMain.handle('auth:isUnlocked', () => !!currentPassword);

// FILES
ipcMain.handle('dialog:openFiles', async (e) => {
  log('dialog:openFiles');
  try {
    const win = BrowserWindow.fromWebContents(e.sender) || mainWindow;
    const result = await dialog.showOpenDialog(win, {
      properties: ['openFile', 'multiSelections'],
      filters: [
        { name: 'All supported', extensions: ['jpg','jpeg','png','gif','bmp','webp','tiff','tif','svg','ico','mp4','avi','mov','mkv','webm','flv','wmv','m4v','3gp','txt','md','json','log','csv'] }
      ]
    });
    log('dialog result: ' + (result.canceled ? 'canceled' : result.filePaths.length + ' files'));
    return result.canceled ? null : result.filePaths;
  } catch (err) {
    log('dialog ERROR: ' + err.message);
    return null;
  }
});

ipcMain.handle('files:add', async (e, filePaths, folderId, tags) => {
  log('files:add, password=' + (currentPassword ? 'YES' : 'NO') + ', files=' + (filePaths ? filePaths.length : 0));
  if (!currentPassword) return { error: 'Vault is locked' };
  if (!filePaths || filePaths.length === 0) return [];
  try {
    const results = [];
    for (const filePath of filePaths) {
      log('  encrypting: ' + filePath);
      const info = fm.addFileToVault(filePath, currentPassword, folderId, tags);
      const thumbName = await fm.generateThumbnail(filePath, info.fileType, currentPassword);
      const dbResult = db.addFile(info.originalName, info.encryptedName, info.fileType, info.mimeType, info.size, folderId, thumbName, tags);
      log('  saved id=' + dbResult.lastInsertRowid);
      results.push({ id: dbResult.lastInsertRowid, ...info, thumbnail: thumbName });
    }
    log('files:add done: ' + results.length + ' files');
    return results;
  } catch (err) {
    log('files:add ERROR: ' + err.message + '\n' + err.stack);
    return { error: err.message };
  }
});

ipcMain.handle('files:list', (e, folderId, fileType, search) => {
  if (!currentPassword) return [];
  try {
    const files = db.getFiles(folderId, fileType, search);
    log('files:list = ' + files.length);
    return files;
  } catch (err) {
    log('files:list ERROR: ' + err.message);
    return [];
  }
});

ipcMain.handle('files:get', (e, id) => {
  if (!currentPassword) return null;
  return db.getFile(id);
});

ipcMain.handle('files:delete', (e, id) => {
  if (!currentPassword) return { success: false };
  const file = db.getFile(id);
  if (file) {
    fm.deleteFileFromDisk(file.encrypted_name);
    fm.deleteThumbnail(file.thumbnail);
    db.deleteFile(id);
  }
  return { success: true };
});

ipcMain.handle('files:getPath', (e, encryptedName) => {
  if (!currentPassword) return null;
  return getDecryptedFilePath(encryptedName, currentPassword);
});

ipcMain.handle('files:updateTags', (e, id, tags) => {
  if (!currentPassword) return { success: false };
  db.updateFileTags(id, tags);
  return { success: true };
});

ipcMain.handle('files:decrypt', async (e, id) => {
  if (!currentPassword) return null;
  const file = db.getFile(id);
  if (!file) return null;
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: file.original_name,
    filters: [{ name: file.original_name, extensions: [file.file_type] }]
  });
  if (!result.canceled) {
    const tempPath = getDecryptedFilePath(file.encrypted_name, currentPassword);
    try { fs.copyFileSync(tempPath, result.filePath); }
    finally { secureCleanupTemp(tempPath); }
    return result.filePath;
  }
  return null;
});

ipcMain.handle('files:getThumbBase64', (e, thumbName) => {
  if (!currentPassword || !thumbName) return null;
  return fm.getDecryptedThumbnailBase64(thumbName, currentPassword);
});

// FOLDERS
ipcMain.handle('folders:add', (e, name, parentId) => {
  if (!currentPassword) return { success: false };
  return { id: db.addFolder(name, parentId).lastInsertRowid };
});
ipcMain.handle('folders:list', (e, parentId) => currentPassword ? db.getFolders(parentId) : []);
ipcMain.handle('folders:get', (e, id) => currentPassword ? db.getFolder(id) : null);
ipcMain.handle('folders:delete', (e, id) => {
  if (!currentPassword) return { success: false };
  db.deleteFolder(id);
  return { success: true };
});

// NOTES
ipcMain.handle('notes:add', (e, title, content, folderId, tags) => {
  if (!currentPassword) return { success: false };
  return { id: db.addNote(title, content, folderId, tags).lastInsertRowid };
});
ipcMain.handle('notes:list', (e, folderId, search) => currentPassword ? db.getNotes(folderId, search) : []);
ipcMain.handle('notes:get', (e, id) => currentPassword ? db.getNote(id) : null);
ipcMain.handle('notes:update', (e, id, title, content, tags) => {
  if (!currentPassword) return { success: false };
  db.updateNote(id, title, content, tags);
  return { success: true };
});
ipcMain.handle('notes:delete', (e, id) => {
  if (!currentPassword) return { success: false };
  db.deleteNote(id);
  return { success: true };
});

// STATS
ipcMain.handle('stats:get', () => {
  if (!currentPassword) return {};
  try { return db.getStats(); } catch { return {}; }
});

// PASSWORDS
ipcMain.handle('passwords:add', (e, name, username, password, url, notes, category, favorite) => {
  if (!currentPassword) return { success: false };
  const result = db.addPassword(name, username, password, url, notes, category, favorite);
  return { id: result.lastInsertRowid };
});
ipcMain.handle('passwords:list', (e, category, search) => currentPassword ? db.getPasswords(category, search) : []);
ipcMain.handle('passwords:get', (e, id) => currentPassword ? db.getPassword(id) : null);
ipcMain.handle('passwords:update', (e, id, name, username, password, url, notes, category, favorite) => {
  if (!currentPassword) return { success: false };
  db.updatePassword(id, name, username, password, url, notes, category, favorite);
  return { success: true };
});
ipcMain.handle('passwords:delete', (e, id) => {
  if (!currentPassword) return { success: false };
  db.deletePassword(id);
  return { success: true };
});
ipcMain.handle('passwords:toggleFavorite', (e, id) => {
  if (!currentPassword) return { success: false };
  db.togglePasswordFavorite(id);
  return { success: true };
});

// WEBAUTHN (Windows Hello / Fingerprint)
ipcMain.handle('webauthn:hasCredential', () => {
  try {
    const creds = db.getAllWebauthnCredentials();
    return creds.length > 0;
  } catch { return false; }
});

ipcMain.handle('webauthn:register', async (e) => {
  if (!currentPassword) return { success: false };
  try {
    const win = BrowserWindow.fromWebContents(e.sender) || mainWindow;
    const challenge = require('crypto').randomBytes(32).toString('base64url');
    const userId = require('crypto').randomBytes(16);

    const options = {
      publicKey: {
        challenge: Buffer.from(challenge, 'base64url'),
        rp: { name: 'Vault', id: 'localhost' },
        user: {
          id: userId,
          name: 'vault-user',
          displayName: 'Vault User'
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -257, type: 'public-key' }
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required'
        },
        timeout: 60000,
        attestation: 'none'
      }
    };

    const credential = await win.webContents.executeJavaScript(
      `navigator.credentials.create(${JSON.stringify(options)})`
    );

    if (!credential) return { success: false, error: 'User cancelled' };

    const credId = Buffer.from(credential.rawId).toString('base64');
    const clientData = Buffer.from(credential.response.clientDataJSON).toString('base64');
    const attestation = Buffer.from(credential.response.attestationObject).toString('base64');

    const id = require('crypto').randomBytes(16).toString('hex');
    db.saveWebauthnCredential(id, credId, JSON.stringify({ clientData, attestation }));

    log('WebAuthn credential registered: ' + id);
    return { success: true };
  } catch (err) {
    log('WebAuthn register error: ' + err.message);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('webauthn:authenticate', async (e) => {
  try {
    const creds = db.getAllWebauthnCredentials();
    if (creds.length === 0) return { success: false, error: 'No credentials registered' };

    const challenge = require('crypto').randomBytes(32).toString('base64url');

    const allowCredentials = creds.map(c => ({
      id: c.credential_id,
      type: 'public-key',
      transports: ['internal']
    }));

    const options = {
      publicKey: {
        challenge: Buffer.from(challenge, 'base64url'),
        timeout: 60000,
        rpId: 'localhost',
        allowCredentials,
        userVerification: 'required'
      }
    };

    const win = BrowserWindow.fromWebContents(e.sender) || mainWindow;
    const assertion = await win.webContents.executeJavaScript(
      `navigator.credentials.get(${JSON.stringify(options)})`
    );

    if (!assertion) return { success: false, error: 'User cancelled' };

    log('WebAuthn authentication successful');
    return { success: true };
  } catch (err) {
    log('WebAuthn auth error: ' + err.message);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('webauthn:delete', (e, id) => {
  if (!currentPassword) return { success: false };
  db.deleteWebauthnCredential(id);
  return { success: true };
});

// WINDOW
ipcMain.handle('window:minimize', () => mainWindow?.minimize());
ipcMain.handle('window:maximize', () => {
  if (mainWindow?.isMaximized()) mainWindow.unmaximize();
  else mainWindow?.maximize();
});
ipcMain.handle('window:close', () => mainWindow?.close());
ipcMain.handle('app:lock', () => {
  currentPassword = null;
  db.clearDbPassword();
  return { success: true };
});

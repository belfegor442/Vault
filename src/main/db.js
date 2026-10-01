const Database = require('better-sqlite3');
const { DB_PATH, VAULT_DIR } = require('../shared/constants');
const fs = require('fs');
const { encryptText, decryptText, secureClear } = require('./crypto');

let db = null;
let dbPassword = null;

function getDb() {
  if (!db) {
    if (!fs.existsSync(VAULT_DIR)) {
      fs.mkdirSync(VAULT_DIR, { recursive: true });
    }
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    initTables();
  }
  return db;
}

function setDbPassword(password) {
  dbPassword = password;
}

function clearDbPassword() {
  if (dbPassword) {
    secureClear(Buffer.from(dbPassword));
  }
  dbPassword = null;
}

function enc(text) {
  if (!text || !dbPassword) return text;
  return encryptText(String(text), dbPassword);
}

function dec(encrypted) {
  if (!encrypted || !dbPassword) return encrypted;
  try {
    return decryptText(encrypted, dbPassword);
  } catch {
    return encrypted;
  }
}

function initTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name_enc TEXT NOT NULL,
      parent_id INTEGER DEFAULT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (parent_id) REFERENCES folders(id)
    );

    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      original_name_enc TEXT NOT NULL,
      encrypted_name TEXT NOT NULL,
      file_type TEXT NOT NULL,
      mime_type_enc TEXT,
      size INTEGER,
      folder_id INTEGER DEFAULT NULL,
      thumbnail_enc TEXT,
      tags_enc TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (folder_id) REFERENCES folders(id)
    );

    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title_enc TEXT NOT NULL,
      content_enc TEXT,
      folder_id INTEGER DEFAULT NULL,
      tags_enc TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (folder_id) REFERENCES folders(id)
    );

    CREATE TABLE IF NOT EXISTS passwords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name_enc TEXT NOT NULL,
      username_enc TEXT DEFAULT '',
      password_enc TEXT NOT NULL,
      url_enc TEXT DEFAULT '',
      notes_enc TEXT DEFAULT '',
      category TEXT DEFAULT 'other',
      favorite INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      id TEXT PRIMARY KEY,
      credential_id_enc TEXT NOT NULL,
      public_key_enc TEXT NOT NULL,
      counter INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function addFile(originalName, encryptedName, fileType, mimeType, size, folderId, thumbnail, tags) {
  const stmt = getDb().prepare(`
    INSERT INTO files (original_name_enc, encrypted_name, file_type, mime_type_enc, size, folder_id, thumbnail_enc, tags_enc)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  return stmt.run(enc(originalName), encryptedName, fileType, enc(mimeType), size, folderId, enc(thumbnail || ''), enc(JSON.stringify(tags || [])));
}

function decryptFileRow(row) {
  if (!row) return null;
  return {
    ...row,
    original_name: dec(row.original_name_enc),
    mime_type: dec(row.mime_type_enc),
    thumbnail: dec(row.thumbnail_enc),
    tags: dec(row.tags_enc)
  };
}

function getFiles(folderId = null, fileType = null, search = null) {
  let query = 'SELECT * FROM files WHERE 1=1';
  const params = [];

  if (folderId) {
    query += ' AND folder_id = ?';
    params.push(folderId);
  } else {
    query += ' AND folder_id IS NULL';
  }

  if (fileType) {
    query += ' AND file_type = ?';
    params.push(fileType);
  }

  query += ' ORDER BY created_at DESC';
  const rows = getDb().prepare(query).all(...params);
  return rows.map(decryptFileRow);
}

function getFile(id) {
  const row = getDb().prepare('SELECT * FROM files WHERE id = ?').get(id);
  return decryptFileRow(row);
}

function deleteFile(id) {
  return getDb().prepare('DELETE FROM files WHERE id = ?').run(id);
}

function updateFileTags(id, tags) {
  return getDb().prepare('UPDATE files SET tags_enc = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(enc(JSON.stringify(tags)), id);
}

function addFolder(name, parentId = null) {
  return getDb().prepare('INSERT INTO folders (name_enc, parent_id) VALUES (?, ?)').run(enc(name), parentId);
}

function decryptFolderRow(row) {
  if (!row) return null;
  return { ...row, name: dec(row.name_enc) };
}

function getFolders(parentId = null) {
  let rows;
  if (parentId) {
    rows = getDb().prepare('SELECT * FROM folders WHERE parent_id = ? ORDER BY id').all(parentId);
  } else {
    rows = getDb().prepare('SELECT * FROM folders WHERE parent_id IS NULL ORDER BY id').all();
  }
  return rows.map(decryptFolderRow);
}

function getFolder(id) {
  const row = getDb().prepare('SELECT * FROM folders WHERE id = ?').get(id);
  return decryptFolderRow(row);
}

function deleteFolder(id) {
  getDb().prepare('UPDATE files SET folder_id = NULL WHERE folder_id = ?').run(id);
  getDb().prepare('UPDATE folders SET parent_id = NULL WHERE parent_id = ?').run(id);
  return getDb().prepare('DELETE FROM folders WHERE id = ?').run(id);
}

function addNote(title, content, folderId = null, tags = []) {
  return getDb().prepare(`
    INSERT INTO notes (title_enc, content_enc, folder_id, tags_enc) VALUES (?, ?, ?, ?)
  `).run(enc(title), enc(content), folderId, enc(JSON.stringify(tags)));
}

function decryptNoteRow(row) {
  if (!row) return null;
  return {
    ...row,
    title: dec(row.title_enc),
    content: dec(row.content_enc),
    tags: dec(row.tags_enc)
  };
}

function getNotes(folderId = null, search = null) {
  let query = 'SELECT * FROM notes WHERE 1=1';
  const params = [];

  if (folderId) {
    query += ' AND folder_id = ?';
    params.push(folderId);
  } else {
    query += ' AND folder_id IS NULL';
  }

  query += ' ORDER BY updated_at DESC';
  const rows = getDb().prepare(query).all(...params);
  return rows.map(decryptNoteRow);
}

function getNote(id) {
  const row = getDb().prepare('SELECT * FROM notes WHERE id = ?').get(id);
  return decryptNoteRow(row);
}

function updateNote(id, title, content, tags) {
  return getDb().prepare(`
    UPDATE notes SET title_enc = ?, content_enc = ?, tags_enc = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
  `).run(enc(title), enc(content), enc(JSON.stringify(tags)), id);
}

function deleteNote(id) {
  return getDb().prepare('DELETE FROM notes WHERE id = ?').run(id);
}

function getStats() {
  const photos = getDb().prepare("SELECT COUNT(*) as count FROM files WHERE file_type = 'photo'").get();
  const videos = getDb().prepare("SELECT COUNT(*) as count FROM files WHERE file_type = 'video'").get();
  const texts = getDb().prepare("SELECT COUNT(*) as count FROM files WHERE file_type = 'text'").get();
  const notes = getDb().prepare('SELECT COUNT(*) as count FROM notes').get();
  const passwords = getDb().prepare('SELECT COUNT(*) as count FROM passwords').get();
  const totalSize = getDb().prepare('SELECT COALESCE(SUM(size), 0) as total FROM files').get();
  const folders = getDb().prepare('SELECT COUNT(*) as count FROM folders').get();

  return {
    photos: photos.count,
    videos: videos.count,
    texts: texts.count,
    notes: notes.count,
    passwords: passwords.count,
    totalSize: totalSize.total,
    folders: folders.count
  };
}

function decryptPasswordRow(row) {
  if (!row) return null;
  return {
    ...row,
    name: dec(row.name_enc),
    username: dec(row.username_enc),
    password: dec(row.password_enc),
    url: dec(row.url_enc),
    notes: dec(row.notes_enc)
  };
}

function addPassword(name, username, password, url, notes, category, favorite) {
  return getDb().prepare(`
    INSERT INTO passwords (name_enc, username_enc, password_enc, url_enc, notes_enc, category, favorite)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(enc(name), enc(username || ''), enc(password), enc(url || ''), enc(notes || ''), category || 'other', favorite ? 1 : 0);
}

function getPasswords(category = null, search = null) {
  let query = 'SELECT * FROM passwords WHERE 1=1';
  const params = [];
  if (category) {
    query += ' AND category = ?';
    params.push(category);
  }
  if (search) {
    query += ' AND (name_enc LIKE ? OR username_enc LIKE ? OR url_enc LIKE ?)';
    const like = '%' + search + '%';
    params.push(like, like, like);
  }
  query += ' ORDER BY favorite DESC, updated_at DESC';
  return getDb().prepare(query).all(...params).map(decryptPasswordRow);
}

function getPassword(id) {
  const row = getDb().prepare('SELECT * FROM passwords WHERE id = ?').get(id);
  return decryptPasswordRow(row);
}

function updatePassword(id, name, username, password, url, notes, category, favorite) {
  return getDb().prepare(`
    UPDATE passwords SET name_enc=?, username_enc=?, password_enc=?, url_enc=?, notes_enc=?, category=?, favorite=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
  `).run(enc(name), enc(username || ''), enc(password), enc(url || ''), enc(notes || ''), category || 'other', favorite ? 1 : 0, id);
}

function deletePassword(id) {
  return getDb().prepare('DELETE FROM passwords WHERE id = ?').run(id);
}

function togglePasswordFavorite(id) {
  return getDb().prepare('UPDATE passwords SET favorite = CASE WHEN favorite = 1 THEN 0 ELSE 1 END, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(id);
}

function saveWebauthnCredential(id, credentialId, publicKey) {
  return getDb().prepare('INSERT INTO webauthn_credentials (id, credential_id_enc, public_key_enc) VALUES (?, ?, ?)').run(id, enc(credentialId), enc(publicKey));
}

function getWebauthnCredential(id) {
  const row = getDb().prepare('SELECT * FROM webauthn_credentials WHERE id = ?').get(id);
  if (!row) return null;
  return { ...row, credential_id: dec(row.credential_id_enc), public_key: dec(row.public_key_enc) };
}

function getAllWebauthnCredentials() {
  return getDb().prepare('SELECT * FROM webauthn_credentials').all().map(row => ({
    ...row,
    credential_id: dec(row.credential_id_enc),
    public_key: dec(row.public_key_enc)
  }));
}

function updateWebauthnCounter(id, counter) {
  return getDb().prepare('UPDATE webauthn_credentials SET counter = ? WHERE id = ?').run(counter, id);
}

function deleteWebauthnCredential(id) {
  return getDb().prepare('DELETE FROM webauthn_credentials WHERE id = ?').run(id);
}

function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
  clearDbPassword();
}

module.exports = {
  addFile, getFiles, getFile, deleteFile, updateFileTags,
  addFolder, getFolders, getFolder, deleteFolder,
  addNote, getNotes, getNote, updateNote, deleteNote,
  addPassword, getPasswords, getPassword, updatePassword, deletePassword, togglePasswordFavorite,
  saveWebauthnCredential, getWebauthnCredential, getAllWebauthnCredentials, updateWebauthnCounter, deleteWebauthnCredential,
  getStats, setDbPassword, clearDbPassword, closeDb, getDb
};

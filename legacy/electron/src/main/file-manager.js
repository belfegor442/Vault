const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { FILES_DIR, THUMBS_DIR, PHOTO_EXTENSIONS, VIDEO_EXTENSIONS } = require('../shared/constants');
const { encryptFile, decryptFile, encryptBuffer, decryptBuffer, secureDelete, secureClear } = require('./crypto');

function ensureDirs() {
  [FILES_DIR, THUMBS_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  });
}

function getFileType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (PHOTO_EXTENSIONS.includes(ext)) return 'photo';
  if (VIDEO_EXTENSIONS.includes(ext)) return 'video';
  return 'text';
}

function generateEncryptedName() {
  return crypto.randomBytes(16).toString('hex');
}

async function generateThumbnail(filePath, fileType, password) {
  if (fileType !== 'photo') return null;
  const thumbName = crypto.randomBytes(16).toString('hex') + '.enc';
  const thumbPath = path.join(THUMBS_DIR, thumbName);
  try {
    encryptFile(filePath, thumbPath, password);
    return thumbName;
  } catch (err) {
    console.error('Thumbnail generation failed:', err.message);
    return null;
  }
}

function getDecryptedThumbnailBase64(thumbName, password) {
  const thumbPath = path.join(THUMBS_DIR, thumbName);
  if (!fs.existsSync(thumbPath)) return null;
  try {
    const encrypted = fs.readFileSync(thumbPath);
    const decrypted = decryptBuffer(encrypted, password);
    const b64 = decrypted.toString('base64');
    secureClear(decrypted);
    return b64;
  } catch { return null; }
}

function addFileToVault(filePath, password, folderId = null, tags = []) {
  ensureDirs();
  const originalName = path.basename(filePath);
  const fileType = getFileType(filePath);
  const mimeType = getMimeType(filePath);
  const stats = fs.statSync(filePath);

  const encryptedName = generateEncryptedName();
  const outputPath = path.join(FILES_DIR, encryptedName);

  encryptFile(filePath, outputPath, password);

  return { originalName, encryptedName, fileType, mimeType, size: stats.size, folderId, tags };
}

function getDecryptedFilePath(encryptedName, password) {
  const encryptedPath = path.join(FILES_DIR, encryptedName);
  if (!fs.existsSync(encryptedPath)) return null;

  const tempPath = path.join(process.env.TEMP || '/tmp', `vault_${crypto.randomBytes(8).toString('hex')}`);
  decryptFile(encryptedPath, tempPath, password);
  return tempPath;
}

function secureCleanupTemp(tempPath) {
  if (!tempPath) return;
  try {
    if (fs.existsSync(tempPath)) {
      secureDelete(tempPath);
    }
  } catch {}
}

function deleteFileFromDisk(encryptedName) {
  const filePath = path.join(FILES_DIR, encryptedName);
  try { secureDelete(filePath); } catch {}
}

function deleteThumbnail(thumbName) {
  if (!thumbName) return;
  const thumbPath = path.join(THUMBS_DIR, thumbName);
  try { secureDelete(thumbPath); } catch {}
}

function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
    '.gif': 'image/gif', '.bmp': 'image/bmp', '.webp': 'image/webp',
    '.tiff': 'image/tiff', '.tif': 'image/tiff', '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.mp4': 'video/mp4', '.avi': 'video/x-msvideo', '.mov': 'video/quicktime',
    '.mkv': 'video/x-matroska', '.webm': 'video/webm', '.flv': 'video/x-flv',
    '.wmv': 'video/x-ms-wmv', '.m4v': 'video/x-m4v', '.3gp': 'video/3gpp',
    '.txt': 'text/plain', '.md': 'text/markdown', '.json': 'application/json',
    '.log': 'text/plain', '.csv': 'text/csv'
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

module.exports = {
  addFileToVault,
  getDecryptedFilePath,
  deleteFileFromDisk,
  deleteThumbnail,
  generateThumbnail,
  getDecryptedThumbnailBase64,
  getFileType,
  secureCleanupTemp,
  THUMBS_DIR
};

const path = require('path');

const VAULT_DIR = path.join(process.env.HOME || process.env.USERPROFILE, '.vault-data');
const FILES_DIR = path.join(VAULT_DIR, 'files');
const THUMBS_DIR = path.join(VAULT_DIR, 'thumbnails');
const DB_PATH = path.join(VAULT_DIR, 'vault.db');
const AUTH_PATH = path.join(VAULT_DIR, 'auth.json');

const PHOTO_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.svg', '.ico'];
const VIDEO_EXTENSIONS = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v', '.3gp'];
const TEXT_EXTENSIONS = ['.txt', '.md', '.json', '.log', '.csv'];

module.exports = {
  VAULT_DIR,
  FILES_DIR,
  THUMBS_DIR,
  DB_PATH,
  AUTH_PATH,
  PHOTO_EXTENSIONS,
  VIDEO_EXTENSIONS,
  TEXT_EXTENSIONS
};

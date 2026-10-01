const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const PBKDF2_ITERATIONS = 600000;
const HKDF_INFO = Buffer.from('vault-file-encryption-v2', 'utf8');
const HKDF_SALT_INFO = Buffer.from('vault-key-derivation-v2', 'utf8');

function deriveKey(password, salt) {
  const preKey = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
  return crypto.hkdfSync('sha512', preKey, salt, HKDF_INFO, KEY_LENGTH);
}

function deriveEncryptionKey(password, salt) {
  const preKey = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
  return Buffer.from(crypto.hkdfSync('sha512', preKey, salt, HKDF_INFO, KEY_LENGTH));
}

function deriveMetaKey(password, salt) {
  const preKey = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
  return Buffer.from(crypto.hkdfSync('sha512', preKey, salt, HKDF_SALT_INFO, KEY_LENGTH));
}

function computeHMAC(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function secureClear(buffer) {
  if (Buffer.isBuffer(buffer)) {
    buffer.fill(0);
  }
}

function encryptBuffer(buffer, password) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveEncryptionKey(password, salt);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const hmac = computeHMAC(key, Buffer.concat([salt, iv, authTag, encrypted]));

  const result = Buffer.alloc(salt.length + iv.length + authTag.length + hmac.length + encrypted.length);
  let offset = 0;
  salt.copy(result, offset); offset += salt.length;
  iv.copy(result, offset); offset += iv.length;
  authTag.copy(result, offset); offset += authTag.length;
  hmac.copy(result, offset); offset += hmac.length;
  encrypted.copy(result, offset);

  secureClear(key);
  return result;
}

function decryptBuffer(encryptedBuffer, password) {
  let offset = 0;
  const salt = encryptedBuffer.subarray(offset, offset + SALT_LENGTH); offset += SALT_LENGTH;
  const iv = encryptedBuffer.subarray(offset, offset + IV_LENGTH); offset += IV_LENGTH;
  const authTag = encryptedBuffer.subarray(offset, offset + AUTH_TAG_LENGTH); offset += AUTH_TAG_LENGTH;
  const storedHmac = encryptedBuffer.subarray(offset, offset + 32); offset += 32;
  const encrypted = encryptedBuffer.subarray(offset);

  const key = deriveEncryptionKey(password, salt);
  const expectedHmac = computeHMAC(key, Buffer.concat([salt, iv, authTag, encrypted]));

  if (!crypto.timingSafeEqual(storedHmac, expectedHmac)) {
    secureClear(key);
    throw new Error('Integrity check failed - data tampered or wrong password');
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  secureClear(key);
  return decrypted;
}

function encryptFile(inputPath, outputPath, password) {
  const buffer = fs.readFileSync(inputPath);
  const encrypted = encryptBuffer(buffer, password);
  fs.writeFileSync(outputPath, encrypted);
  secureClear(buffer);
  secureClear(encrypted);
}

function decryptFile(inputPath, outputPath, password) {
  const encrypted = fs.readFileSync(inputPath);
  const decrypted = decryptBuffer(encrypted, password);
  fs.writeFileSync(outputPath, decrypted);
  secureClear(encrypted);
}

function encryptText(text, password) {
  const buffer = Buffer.from(text, 'utf8');
  const encrypted = encryptBuffer(buffer, password);
  const result = encrypted.toString('base64');
  secureClear(buffer);
  return result;
}

function decryptText(encryptedBase64, password) {
  const encrypted = Buffer.from(encryptedBase64, 'base64');
  const decrypted = decryptBuffer(encrypted, password);
  const result = decrypted.toString('utf8');
  secureClear(encrypted);
  return result;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const preHash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
  const hash = crypto.pbkdf2Sync(preHash, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
  secureClear(preHash);
  return {
    salt: salt.toString('hex'),
    hash: hash.toString('hex'),
    iterations: PBKDF2_ITERATIONS,
    version: 2
  };
}

function verifyPassword(password, stored) {
  const salt = Buffer.from(stored.salt, 'hex');
  const preHash = crypto.pbkdf2Sync(password, salt, stored.iterations || PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
  const hash = crypto.pbkdf2Sync(preHash, salt, stored.iterations || PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
  const result = crypto.timingSafeEqual(hash, Buffer.from(stored.hash, 'hex'));
  secureClear(preHash);
  secureClear(hash);
  return result;
}

function secureDelete(filePath) {
  try {
    if (!fs.existsSync(filePath)) return;
    const stats = fs.statSync(filePath);
    const fd = fs.openSync(filePath, 'r+');
    const buf = Buffer.alloc(4096);
    for (let i = 0; i < Math.ceil(stats.size / 4096); i++) {
      crypto.randomFillSync(buf);
      fs.writeSync(fd, buf, 0, buf.length, i * 4096);
    }
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fs.unlinkSync(filePath);
  } catch {}
}

module.exports = {
  encryptBuffer,
  decryptBuffer,
  encryptFile,
  decryptFile,
  encryptText,
  decryptText,
  hashPassword,
  verifyPassword,
  secureClear,
  secureDelete
};

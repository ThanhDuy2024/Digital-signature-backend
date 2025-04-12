// generateKeys.js
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const keyDir = path.join(__dirname, 'keys');
if (!fs.existsSync(keyDir)) fs.mkdirSync(keyDir);

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

fs.writeFileSync(path.join(keyDir, 'private.pem'), privateKey);
fs.writeFileSync(path.join(keyDir, 'public.pem'), publicKey);

console.log('Đã tạo xong khóa: private.pem và public.pem');

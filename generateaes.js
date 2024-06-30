const crypto = require('crypto');
require('dotenv').config();

const aesKey = process.env.AES_MASTER_KEY; // 256-bit AES key
console.log('AES Key :', aesKey);

const aesKeyBase64 = aesKey.toString('base64');
console.log('AES Key (Base64):', aesKeyBase64);

const aes = Buffer.from(aesKeyBase64, 'base64');
console.log('AES Key :', aes)

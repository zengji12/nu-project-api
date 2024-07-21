const crypto = require('crypto');
const { generateKeyPair } = require('crypto');

async function generateRSAKeyPair(aesKey) {
    const { publicKey, privateKey } = await new Promise((resolve, reject) => {
        generateKeyPair('rsa', {
            modulusLength: 2048,
        }, (err, publicKey, privateKey) => {
            if (err) reject(err);
            else resolve({ publicKey, privateKey });
        });
    });

    const publicKeyPem = publicKey.export({ type: 'pkcs1', format: 'pem' });
    const privateKeyPem = privateKey.export({ type: 'pkcs1', format: 'pem' });

    const encryptedPrivateKey = await encryptKey(privateKeyPem, aesKey);
    const encryptedPublicKey = await encryptKey(publicKeyPem, aesKey);

    return { 
        publicKey: encryptedPublicKey.encrypted,
        privateKey: encryptedPrivateKey.encrypted,
        publicKeyIv: encryptedPublicKey.iv,
        privateKeyIv: encryptedPrivateKey.iv,
        publicKeyAuthTag: encryptedPublicKey.authTag,
        privateKeyAuthTag: encryptedPrivateKey.authTag
    };
}

async function encryptKey(keyPem, aesKey, iv='') {
    if (!iv) {
        iv = crypto.randomBytes(16);
    } else {
        iv = Buffer.from(iv, 'base64');
    }

    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);

    let encrypted = cipher.update(keyPem, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();

    return { iv: iv.toString('base64'), encrypted, authTag: authTag.toString('base64') };
}

function decryptKey(encryptedKey, aesKey, iv, authTag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(authTag, 'base64'));

    let decrypted = decipher.update(encryptedKey, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Fungsi untuk enkripsi menggunakan XOR sederhana
async function encrypt(text, password) {
    const textChars = text.split('');
    const passwordChars = password.split('');
    let encryptedText = '';
    
    for (let i = 0; i < textChars.length; i++) {
        encryptedText += String.fromCharCode(
            textChars[i].charCodeAt(0) ^ passwordChars[i % passwordChars.length].charCodeAt(0)
        );
    }
    
    return Buffer.from(encryptedText).toString('base64'); // Mengubah hasil enkripsi menjadi base64 untuk penyimpanan
}

// Fungsi untuk dekripsi menggunakan XOR sederhana
async function decrypt(encryptedText, password) {
    const encryptedChars = Buffer.from(encryptedText, 'base64').toString('binary').split('');
    const passwordChars = password.split('');
    let decryptedText = '';
    
    for (let i = 0; i < encryptedChars.length; i++) {
        decryptedText += String.fromCharCode(
            encryptedChars[i].charCodeAt(0) ^ passwordChars[i % passwordChars.length].charCodeAt(0)
        );
    }
    
    return decryptedText;
}

async function encryptRSA(publicKeyPem, data) {
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const buffer = Buffer.from(data, 'utf8');
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
}

async function decryptRSA(privateKeyPem, data) {
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const buffer = Buffer.from(data, 'base64');
    const decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString('utf8');
}

module.exports = { generateRSAKeyPair, encryptKey, decryptKey, decrypt, encrypt, encryptRSA, decryptRSA };

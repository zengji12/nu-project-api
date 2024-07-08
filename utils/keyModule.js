const crypto = require('crypto');
const { promisify } = require('util');

const generateKeyPair = promisify(crypto.generateKeyPair);

async function generateRSAKeyPair(aesKey) {
    const { publicKey, privateKey } = await generateKeyPair('rsa', {
        modulusLength: 2048,
    });

    const publicKeyHex = publicKey.export({ type: 'pkcs1', format: 'der' }).toString('hex');
    const privateKeyHex = privateKey.export({ type: 'pkcs1', format: 'der' }).toString('hex');

    const { iv, encrypted, authTag } = await encryptPrivateKey(privateKeyHex, aesKey);
    return { 
        publicKey: publicKeyHex,
        encryptedKey: encrypted,
        iv: iv,
        authTag: authTag
    };
}

async function encryptPrivateKey(privateKeyHex, aesKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('AES-256-GCM', aesKey, iv);

    let encrypted = cipher.update(privateKeyHex, 'hex', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag(); // Get authTag directly as Buffer

    return { iv: iv.toString('base64'), encrypted, authTag };
}

function decryptPrivateKey(encryptedPrivateKey, aesKey, iv, authTag) {
    const decipher = crypto.createDecipheriv('AES-256-GCM', aesKey, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(authTag); // Set authTag directly as Buffer

    let decrypted = decipher.update(encryptedPrivateKey, 'base64', 'hex');
    decrypted += decipher.final('hex');
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

module.exports = { generateRSAKeyPair, encryptPrivateKey, decryptPrivateKey, decrypt, encrypt };

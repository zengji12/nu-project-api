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


function encryptWithPublicKey(publicKey, data) {
    const publicKeyObj = crypto.createPublicKey({
        key: Buffer.from(publicKey, 'hex'),
        format: 'der',
        type: 'pkcs1'
    });

    const encryptedData = crypto.publicEncrypt({
        key: publicKeyObj,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, Buffer.from(data));

    return encryptedData.toString('base64');
}

async function encryptWithPrivateKey(encryptedPrivateKey, iv, aesKey, authTag, data) {
    const decryptedPrivateKey = decryptPrivateKey(encryptedPrivateKey, aesKey, iv, authTag);

    const privateKeyObj = crypto.createPrivateKey({
        key: Buffer.from(decryptedPrivateKey, 'hex'),
        format: 'der',
        type: 'pkcs1'
    });

    const encryptedData = crypto.privateEncrypt({
        key: privateKeyObj,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, Buffer.from(data));

    const encryptedString = encryptedData.toString('base64');
    return encryptedString;
}

module.exports = { generateRSAKeyPair, encryptPrivateKey, decryptPrivateKey, encryptWithPublicKey, encryptWithPrivateKey };

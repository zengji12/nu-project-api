const crypto = require('crypto');
const { promisify } = require('util');

const generateKeyPair = promisify(crypto.generateKeyPair);

async function generateRSAKeyPair(aesKey) {
    const { publicKey, privateKey } = await generateKeyPair('rsa', {
        modulusLength: 2048,
    });

    const publicKeyHex = publicKey.export({ type: 'pkcs1', format: 'der' }).toString('hex');
    const privateKeyHex = privateKey.export({ type: 'pkcs1', format: 'der' }).toString('hex');

    const { iv, encrypted } = await encryptPrivateKey(privateKeyHex, aesKey, null);
    return { 
        publicKey: publicKeyHex,
        encryptedKey: encrypted,
        iv: iv
    };
}

async function encryptPrivateKey(privateKeyHex, aesKey, iv) {
    if (!iv){
        iv = crypto.randomBytes(16);
    }
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(privateKeyHex, 'hex', 'base64');
    encrypted += cipher.final('base64');
    return { iv: iv.toString('base64'), encrypted };
}

function decryptPrivateKey(encryptedPrivateKey, aesKey, iv) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, Buffer.from(iv, 'base64'));
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

async function encryptWithPrivateKey(encryptedPrivateKey, iv, aesKey, data) {
    const decryptedPrivateKey = decryptPrivateKey(encryptedPrivateKey, aesKey, iv);

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
    // console.log('Encrypted data:', encryptedString);
    // console.log('it is string?', typeof encryptedString === 'string');
    return encryptedString;
}

module.exports = { generateRSAKeyPair, encryptPrivateKey, decryptPrivateKey, encryptWithPublicKey, encryptWithPrivateKey };

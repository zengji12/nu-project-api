const { encryptPrivateKey, decryptPrivateKey, generateRSAKeyPair } = require('./utils/keyModule');
const crypto = require('crypto');

(async () => {
    try {
        // Generate RSA key pair
        const { publicKey, privateKey } = await generateRSAKeyPair();
        console.log('Public Key:', publicKey);
        console.log('Private Key:', privateKey);

        // Generate AES key
        const aesKey = crypto.randomBytes(32);

        // Encrypt the private key
        const { iv, encrypted } = await encryptPrivateKey(privateKey, aesKey);
        console.log('Encrypted Private Key:', encrypted);
        console.log('IV:', iv);

        // Decrypt the private key
        const decryptedPrivateKey = await decryptPrivateKey(encrypted, aesKey, iv);
        console.log('Decrypted Private Key:', decryptedPrivateKey);

        console.log('Public Key Length:', publicKey.length);
        console.log('Private Key Length:', privateKey.length);
        console.log('Encrypted Private Key Length:', encrypted.length);
        console.log('Decrypted Private Key Length:', decryptedPrivateKey.length);

    } catch (err) {
        console.error('Error:', err);
    }
})();

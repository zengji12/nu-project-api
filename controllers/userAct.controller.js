const db = require("../models");
const config = require("../configs/auth.config");
const User = db.users;
const dKeys = db.userKey;
const djunkKeys = db.userjunkKey;
const mhand = db.handshake;
const { validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const { generateRSAKeyPair, encrypt, decryptKey, decrypt, encryptRSA, decryptRSA } = require('../utils/keyModule')

exports.new = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { id: userId, name, username, password, alamat } = req.body;

        if (!userId || !name || !username || !password || !alamat) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const hashedPassword = bcrypt.hashSync(password, 8);

        const aesKey = Buffer.from(config.master, 'base64');
        const userKey = await generateRSAKeyPair(aesKey);
        const encryptedAlamat = await encrypt(alamat, password);

        const user = await User.create({
            userId: userId,
            fullname: name,
            username: username,
            password: hashedPassword,
            alamat: encryptedAlamat
        });

        await dKeys.create({
            userId: user.userId,
            label: "your first key pair",
            public: userKey.publicKey,
            private: userKey.privateKey,
            publicKeyIv: userKey.publicKeyIv,
            privateKeyIv: userKey.privateKeyIv,
            publicKeyAuthTag: userKey.publicKeyAuthTag,
            privateKeyAuthTag: userKey.privateKeyAuthTag
        });

        console.log(`[new user added][${new Date()}] ${name} has joined`);
        return res.status(200).json({ message: `New user has been added ${userId}` });
    } catch (error) {
        console.error("Error generating new user:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

exports.delete = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try{
        const userId = req.userId;
        const duser = await User.findOne({ where: { userId: userId } });

        if (duser){
            const ouser = await dKeys.findAll({ where: { userId: duser.userId } });

            if (ouser.length > 0) {
                
                await Promise.all(ouser.map(async (key) => {
                    try {
                        await djunkKeys.create({
                            userId: key.userId,
                            public: key.publicKey,
                            private: key.privateKey,
                            publicKeyIv: key.publicKeyIv,
                            privateKeyIv: key.privateKeyIv,
                            publicKeyAuthTag: key.publicKeyAuthTag,
                            privateKeyAuthTag: key.privateKeyAuthTag
                        });
                    } catch (error) {
                        console.error(`Error saving key to junk keys:`, error);
                    }
                }));
            }
            console.log(`[deleted user key][${new Date()}] ${ouser.length} saved to junk keys successfully`);
            await User.destroy({ where: { userId: userId } });

            console.log(`[deleted user][${new Date()}] ${duser.fullname} has been deleted`);
            return res.status(200).json({ message: `user with id ${userId} successfully deleted.` });
        } else {
            return res.status(404).json({ message: `User with id ${userId} not found.` });
        }
    }catch (error) {
        console.error("Error deleting user:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
}

exports.newPass = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const oldPass = req.body.oldPass;
    const newPass = req.body.newPass;
    const token = req.headers['x-access-token'] || req.body.token;

    if (!token) {
        return res.status(403).json({ message: "No token provided!" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.userId;

        const user = await User.findOne({ where: { userId: userId } });

        if (!user) {
            return res.status(404).json({ message: "user not found!" });
        }

        const passwordIsValid = await bcrypt.compare(oldPass, user.password);

        if (!passwordIsValid) {
            return res.status(401).json({ message: "Invalid old password!" });
        }

        const newAlamat = await decrypt(user.alamat, oldPass);
        const encryptedAlamat = await encrypt(newAlamat, newPass);

        const hashedNewPass = await bcrypt.hash(newPass, 8);
        user.alamat = encryptedAlamat;
        user.password = hashedNewPass;
        await user.save();

        console.log(`[change password][${new Date()}] user ${userId} is renew password`);
        return res.status(200).json({ message: "Password updated successfully!" });
    } catch (error) {
        console.error("Error renewing password:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

exports.newKey = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const userId = req.userId;
        const label = req.body.label;

        const existingKeys = await dKeys.findAll({ where: { userId: userId } });
        if (existingKeys.length >= 3) {
            return res.status(400).json({ message: "User already has 3 key pairs." });
        }

        const existingLabel = await dKeys.findOne({ where: { userId: userId, label: label } });
        if (existingLabel) {
            return res.status(400).json({ message: "Label already exists." });
        }

        const aesKey = Buffer.from(config.master, 'base64');
        const keyPair = await generateRSAKeyPair(aesKey);
        if (!keyPair) {
            throw new Error("Key pair generation failed");
        }

        const newKey = await dKeys.create({
            userId: userId,
            label: label,
            public: keyPair.publicKey,
            private: keyPair.privateKey,
            publicKeyIv: keyPair.publicKeyIv,
            privateKeyIv: keyPair.privateKeyIv,
            publicKeyAuthTag: keyPair.publicKeyAuthTag,
            privateKeyAuthTag: keyPair.privateKeyAuthTag
        });

        console.log(`[new key][${new Date()}] user ${userId} is making new key`);
        res.status(201).json(newKey);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

exports.deleteKey = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const userId = req.userId;
    const label = req.body.label;
    const privateKey = req.body.privateKey;

    try {
        const key = await dKeys.findOne({
            where: {
                userId: userId,
                label: label
            }
        });

        if (!key) {
            return res.status(404).json({ message: "Key not found" });
        }

        const aesKey = Buffer.from(config.master, 'base64');
        const ivKey = Buffer.from(key.privateKeyIv, 'base64');
        const authKey = Buffer.from(key.privateKeyAuthTag, 'base64');

        const decrypted= await decryptKey(key.private, aesKey, ivKey, authKey);

        if (privateKey !== decrypted) {
            return res.status(400).json({ message: "Private key does not match" });
        }

        await djunkKeys.create({
            userId: key.userId,
            public: key.public,
            private: key.private,
            publicKeyIv: key.publicKeyIv,
            privateKeyIv: key.privateKeyIv,
            publicKeyAuthTag: key.publicKeyAuthTag,
            privateKeyAuthTag: key.privateKeyAuthTag
        });

        await dKeys.destroy({
            where: {
                userId: userId,
                label: label
            }
        });

        console.log(`[delete key][${new Date()}] user ${userId} has deleted one of their keys`);
        return res.status(200).json({ message: "Key deleted successfully" });
    } catch (error) {
        console.error("Error deleting key:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

exports.getKey = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const userId = req.userId

    try{
        const userKeys = await dKeys.findAll({ where: { userId: userId } });

        const aesKey = Buffer.from(config.master, 'base64');

        const decryptedUserKeys = userKeys.map(key => {
            const decryptedPrivateKey = decryptKey(key.private, aesKey, key.privateKeyIv, key.privateKeyAuthTag);
            const decryptedPublicKey = decryptKey(key.public, aesKey, key.publicKeyIv, key.publicKeyAuthTag);
            return {
                label: key.label,
                public: decryptedPublicKey,
                private: decryptedPrivateKey
            };
        });

        return res.status(200).json(decryptedUserKeys);
    } catch (error) {
        console.error("Error getting key:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

exports.handshake = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const userId = req.userId;

    try {
        const acceptedHandshakes = await mhand.findAll({
            where: {
                userId: userId,
                condition: 'accept'
            }
        });
        res.json(acceptedHandshakes);
    } catch (error) {
        console.error('Error retrieving handshakes:', error);
        res.status(500).json({ error: 'An error occurred while retrieving handshakes' });
    }
};

exports.makeHandshake = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const toUser = req.body.id;
    const myLabel = req.body.label;
    const userId = req.userId;

    try{
        await User.findOne({where:{userId:toUser}}).then(()=>{
            mhand.create({
                userId: userId,
                toUserId: toUser,
                labelMe: myLabel,
                condition:'waiting'
            });
        });
        
        console.log(`[make handshake][${new Date()}] user ${userId} make handshake to ${toUser}`);
        return res.status(200).json({ message: "Handshake successfully" });
    } catch(error){
        console.error("Error getting hand:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

exports.getHandshake = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const userId = req.userId;

    try {
        // Temukan semua handshakes dengan kondisi 'waiting'
        const waitingHandshakes = await mhand.findAll({
            where: {
                toUserId: userId,
                condition: 'accept'
            },
            include: [
                {
                    model: User,
                    as: 'User',
                    attributes: ['userId', 'fullname'] // Include only necessary attributes
                }
            ]
        });

        // Map the result to return only the necessary information
        const response = waitingHandshakes.map(handshake => ({
            user: {
                userId: handshake.User.userId,
                fullname: handshake.User.fullname
            },
            labelMe: handshake.labelMe,
            labelYou: handshake.labelYou
        }));

        res.status(201).json(response);
    } catch (error) {
        console.error('Error retrieving handshakes:', error);
        res.status(500).json({ error: 'An error occurred while retrieving handshakes' });
    }
};

exports.requestHandshake = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const userId = req.userId;

    try {
        const waitingHandshakes = await mhand.findAll({
            where: {
                toUserId: userId,
                condition: 'waiting'
            },
            include: [
                {
                    model: User,
                    as: 'User',
                    attributes: ['userId', 'fullname'] // Include only necessary attributes
                }
            ]
        });

        const response = waitingHandshakes.map(handshake => ({
            reqUserId: handshake.userId,
            user: {
                userId: handshake.User.userId,
                fullname: handshake.User.fullname
            },
            labelMe: handshake.labelMe
        }));

        res.status(201).json(response);
    } catch (error) {
        console.error('Error retrieving handshakes:', error);
        res.status(500).json({ error: 'An error occurred while retrieving handshakes' });
    }
};

exports.acceptHandshake = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const userId = req.userId;
    const { reqUserId, labelYou } = req.body;

    try {
        const toAcc = await mhand.findOne({ where: { toUserId: userId, userId: reqUserId } });

        if (toAcc) {
            toAcc.labelYou = labelYou;
            toAcc.condition = 'accept';
            await toAcc.save();

            console.log(`[make handshake][${new Date()}] user ${userId} accepted handshake from ${reqUserId}`);
            return res.status(200).json({ message: "Handshake successfully accepted" });
        } else {
            return res.status(400).json({ message: "No handshake request found" });
        }
    } catch (error) {
        console.error("Error accepting handshake:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

exports.declineHandshake = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const userId = req.userId;
    const { reqUserId } = req.body;

    try {
        const toAcc = await mhand.findOne({ where: { toUserId: userId, userId: reqUserId } });

        if (toAcc) {
            toAcc.condition = 'decline';
            await toAcc.save();

            console.log(`[make handshake][${new Date()}] user ${userId} declined handshake from ${reqUserId}`);
            return res.status(200).json({ message: "Handshake successfully declined" });
        } else {
            return res.status(400).json({ message: "No handshake request found" });
        }
    } catch (error) {
        console.error("Error declining handshake:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

async function encryptData (data, userId, label) {
    const key = await dKeys.findOne({where:{userId:userId, label:label}});

    const aesKey = Buffer.from(config.master, 'base64');

    const decryptedKey = decryptKey(key.public, aesKey, key.publicKeyIv, key.publicKeyAuthTag);
    return encryptRSA(decryptedKey, data);
};

async function decryptData (data, userId, label) {
    const key = await dKeys.findOne({where:{userId:userId, label:label}});

    const aesKey = Buffer.from(config.master, 'base64');

    const decryptedKey = decryptKey(key.private, aesKey, key.privateKeyIv, key.privateKeyAuthTag);

    return decryptRSA(decryptedKey, data);
};

exports.communicateEncrypt = async (req, res) => {
    const { targetUserId, label, message } = req.body;

    if (!targetUserId || !label || !message) {
        return res.status(400).json({ error: 'Missing targetUserId, label, or message in request body' });
    }

    const userId = req.userId;

    try {
        const handshake = await mhand.findOne({
            where: {
                userId: userId,
                toUserId: targetUserId,
                condition: 'accept'
            }
        });

        if (!handshake) {
            return res.status(400).json({ error: 'No accepted handshake found with the specified user' });
        }

        const encryptedMessage = await encryptData(message, handshake.toUserId, label);

        console.log(encryptedMessage);

        res.status(200).json({ encryptedMessage });
    } catch (error) {
        console.error('Error communicating with accepted user:', error);
        res.status(500).json({ error: 'An error occurred while communicating with accepted user' });
    }
};

exports.communicateDecrypt = async (req, res) => {
    const { label, message } = req.body;
    const userId = req.userId;

    try {
        const decryptedMessage = await decryptData(message, userId, label);

        res.status(200).json({ decryptedMessage });
    } catch (error) {
        console.error('Error communicating with accepted user:', error);
        res.status(500).json({ error: 'An error occurred while communicating with accepted user' });
    }
};
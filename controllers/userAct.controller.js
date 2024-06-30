const db = require("../models");
const config = require("../configs/auth.config");
const User = db.users;
const dKeys = db.userKey;
const djunkKeys = db.userjunkKey;
const { validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const { generateRSAKeyPair, encryptWithPrivateKey, decryptPrivateKey, encryptPrivateKey } = require('../utils/keyModule')

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
        const { publicKey, encryptedKey, iv } = await generateRSAKeyPair(aesKey);
        const encryptedAlamat = await encryptWithPrivateKey(encryptedKey, iv, aesKey, alamat);

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
            public: publicKey,
            private: encryptedKey,
            iv: iv
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
                            public: key.public,
                            private: key.private,
                            iv: key.iv
                        });
                    } catch (error) {
                        console.error(`Error saving key to junk keys:`, error);
                    }
                }));
            
                console.log(`[deleted user][${new Date()}] ${ouser.length} saved to junk keys successfully`);

                await User.destroy({ where: { userId: userId } });

                console.log(`[deleted user][${new Date()}] ${duser.fullname} has been deleted`);
                return res.status(200).json({ message: `user with id ${userId} successfully deleted.` });
            } else {
                    return res.status(404).json({ message: `User with id ${userId} not found.` });
            }
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

        const hashedNewPass = await bcrypt.hash(newPass, 8);
        user.password = hashedNewPass;
        await user.save();

        console.log(`[change password][${new Date()}] user ${userId} is renew password`);
        return res.status(200).json({ message: "Password updated successfully!" });
    } catch (error) {
        console.error("Error renewing password:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

const galat = Promise.reject(new Error('skip'));

exports.newKey = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const userId = req.userId;
    const label = req.body.label;

    dKeys.findAll({ where: { userId: userId } })
        .then(existingKeys => {
            if (existingKeys.length >= 3) {
                res.status(400).json({ message: "User already has 3 key pairs." });
                return galat;
            }

            return dKeys.findOne({ where: { userId: userId, label: label } });
        })
        .then(existingLabel => {
            if (existingLabel) {
                res.status(400).json({ message: "Label already exists." });
                return galat;
            }

            const aesKey = Buffer.from(config.master, 'base64');
            return generateRSAKeyPair(aesKey);
        })
        .then(keyPair => {
            if (!keyPair) {
                throw new Error("Key pair generation failed");
            }

            const { publicKey, encryptedKey, iv } = keyPair;

            if (!publicKey || !encryptedKey || !iv) {
                res.status(500).json({ message: "Key pair generation failed" });
                return galat;  
            }

            return dKeys.create({
                userId: userId,
                label: label,
                public: publicKey,
                private: encryptedKey,
                iv: iv
            });
        })
        .then(newKey => {
            console.log(`[new key][${new Date()}] user ${userId} is making new key`);
            res.status(201).json(newKey);
        })
        .catch(error => {
            if (error.message !== 'skip') {
                console.error(error);
                res.status(500).json({ message: "Internal server error" });
            }
        });
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
        const ivKey = Buffer.from(key.iv, 'base64');

        const { encrypted } = await encryptPrivateKey(privateKey, aesKey, ivKey);

        if (key.private !== encrypted) {
            return res.status(400).json({ message: "Private key does not match" });
        }

        await djunkKeys.create({
            userId: key.userId,
            public: key.public,
            private: key.private,
            iv: key.iv
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
            const decryptedPrivateKey = decryptPrivateKey(key.private, aesKey, key.iv);
            return {
                label: key.label,
                public: key.public,
                private: decryptedPrivateKey
            };
        });

        return res.status(200).json(decryptedUserKeys);
    } catch (error) {
        console.error("Error getting key:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};
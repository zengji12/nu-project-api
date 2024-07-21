const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const config = require("../configs/auth.config");
const db = require("../models");
const dKeys = db.userKey;
const djunkKeys = db.userjunkKey;
const User = db.users;
const { validationResult } = require('express-validator');
const { response } = require("express");
const { decrypt } = require('../utils/keyModule');

exports.signin = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ where: { username } });

    if (!user) {
      return res.status(401).json({ message: "Username not found" });
    }

    const passwordIsValid = await bcrypt.compare(password, user.password);

    if (!passwordIsValid) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign({ userId: user.userId, username: user.username }, config.secret, {
      expiresIn: 86400, // 24 jam
    });

    const decryptedAlamat = await decrypt(user.alamat, password);

    res.status(200).json({
        address: decryptedAlamat,
        name: user.fullname,
        accessToken: token
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

exports.refreshToken = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).send({ message: "Invalid input", errors: errors.array() });
  }

  let token = req.headers.authorization;
  if (!token) {
    return res.status(403).send({
      message: "No token provided!",
    });
  }

  token = token.split(" ")[1];

  jwt.verify(token, config.secret, { ignoreExpiration: true }, (err, decoded) => {
    if (err || !decoded.username) {
      return res.status(403).send({
        message: "Invalid token!",
      });
    }

    User.findOne({
      where: {
        username: decoded.username,
      },
    })
      .then((user) => {
        if (!user) {
          return res.status(404).send({ message: "User not found." });
        }

        const newToken = jwt.sign({ username: user.username }, config.secret, {
          expiresIn: 86400, // 24 hours
        });
        
        res.status(200).send({
          username: user.username,
          accessToken: newToken,
        });
      })
      .catch((err) => {
        console.log(err);
        res.status(500).send({ message: err.message });
      });
  });
};

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

exports.deleteuser = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).send({ message: "Invalid input", errors: errors.array() });
  }
  const userId = req.body.userId;

  let token = req.headers.authorization;
  if (!token) {
    return res.status(403).send({
      message: "No token provided!",
    });
  }

  token = token.split(" ")[1];

  jwt.verify(token, config.secret, { ignoreExpiration: true }, async (err, decoded) => {
    if (err || !decoded.username) {
      return res.status(403).send({
        message: "Invalid token!",
      });
    }

    try {
      const ouser = await dKeys.findAll({
        where: {
          userId: userId,
        },
      });

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

      await User.destroy({
        where: {
          userId: userId,
        },
      });

      console.log(`[admin delete user][${new Date()}] ${decoded.username} deleted user with ID ${userId}`);
      res.status(200).send({ message: "Admin deleting User successfully." });
    } catch (err) {
      console.log(err);
      res.status(500).send({ message: err.message });
    }
  });
};

exports.checkAdmin = (req, res) => {
  res.status(200).json({ isAdmin: true });
};

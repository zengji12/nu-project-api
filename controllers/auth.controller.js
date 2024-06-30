const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const config = require("../configs/auth.config");
const db = require("../models");
const dKeys = db.userKey;
const djunkKeys = db.userjunkKey;
const User = db.users;
const { validationResult } = require('express-validator');
const { response } = require("express");

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

    res.status(200).json({
        userId: user.userId,
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

exports.changePassword = (req, res) => {
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
              username: decoded.username
          }
      }).then(user => {
          if (!user) {
              return res.status(401).send({ message: "User Not found." });
          }

          var passwordIsValid = bcrypt.compareSync(
              req.body.password,
              user.password
          );

          if (!passwordIsValid) {
              return res.status(401).send({
                  accessToken: null,
                  message: "Invalid Password!"
              });
          } else {
              User.update({
                  password: bcrypt.hashSync(req.body.newPassword, 8)
              }, {
                  where: { username: decoded.username }
              }).then(user => {
                  console.log(`[auth password change][${new Date()}] ${user.username} change password`);
                  res.send({ message: "Password changed successfully!" });
              }).catch(err => {
                  res.status(500).send({ message: err.message });
              });
          }
      }).catch(err => {
          res.status(500).send({ message: err.message });
      });
  });
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
              public: key.public,
              private: key.private,
              iv: key.iv,
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

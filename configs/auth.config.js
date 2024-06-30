require('dotenv').config()

module.exports = {
    secret: process.env.AUTH_SECRET_KEY,
    master: process.env.AES_MASTER_KEY
};
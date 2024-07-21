const express = require("express");
const app = express();
const fs = require("fs");
const https = require("https");
require('dotenv').config();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    const data = { message: 'Hello from Node.js API!' };
    res.json(data);
});

const db = require("./models");

db.sequelize.sync().then(() => {
    console.log('db synced');
}).catch(err => {
    console.log(err.message);
});

require('./routes/auth.routes.js')(app);
require('./routes/user.routes.js')(app);
require('./routes/comunicate.routes.js')(app);

if (process.env.SSL_MODE === 'ON') {
    const https_options = {
        key: fs.readFileSync(process.env.SSL_KEYPATH),
        cert: fs.readFileSync(process.env.SSL_CERTPATH),
        ca: [
            fs.readFileSync(process.env.SSL_CERTPATH),
            fs.readFileSync(process.env.SSL_CABUNDLEPATH)
        ]
    };
    const HTTPSPORT = process.env.HTTPS_PORT || 5080;
    https.createServer(https_options, app).listen(HTTPSPORT, 'localhost', () => {
        console.log(`Project server is running on ${HTTPSPORT}.`);
    });
}

const PORT = process.env.HTTP_PORT || 5443;
app.listen(PORT, () => {
  console.log(`Project server is running on ${PORT}.`);
});

process.on('SIGINT', () => { console.log("Bye bye!"); process.exit(); });
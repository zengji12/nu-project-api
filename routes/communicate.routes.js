const controller = require("../controllers/userAct.controller");
const { authJwt, authAdmin, } = require("../middleware");
const { body } = require('express-validator');

module.exports = function(app) {
    app.use(function(req, res, next) {
        res.header(
            "Access-Control-Allow-Headers",
            "x-access-token, Origin, Content-Type, Accept"
        );
        next();
    });

    app.post("/api/communicate/encrypt",[
        authJwt.verifyToken,
        body("targetUserId").isLength({min:1}),
        body("label").isLength({min:1}),
        body("message").isLength({min:1})
    ], controller.communicateEncrypt);

    app.post("/api/communicate/decrypt",[
        authJwt.verifyToken,
        body("label").isLength({min:1}),
        body("message").isLength({min:1})
    ], controller.communicateDecrypt);
}
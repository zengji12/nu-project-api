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

    app.post("/api/user/register",[
        authJwt.verifyToken,
        authAdmin.isAdmin,
        body("id").isLength({min: 1}),
        body("name").isLength({min: 1}),
        body("username").isLength({min: 1}),
        body("password").trim().notEmpty().withMessage('Password cannot be empty').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
        body("alamat").isLength({min: 1})
    ], controller.new);
    
    app.post("/api/user/delete",[
        authJwt.verifyToken
    ], controller.delete);

    app.post("/api/user/newkey",[
        authJwt.verifyToken,
        body("label").isLength({min: 1})
    ], controller.newKey);

    app.post("/api/user/deletekey",[
        authJwt.verifyToken,
        body("label").isLength({min: 1}),
        body("privateKey").isLength({min:1})
    ], controller.deleteKey)

    app.post("/api/user/getkey",[
        authJwt.verifyToken
    ], controller.getKey);
}
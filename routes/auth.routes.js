const controller = require("../controllers/auth.controller");
const { authAdmin } = require("../middleware");
const authJwt = require("../middleware/authJwt");
const { body } = require('express-validator');

module.exports = function(app) {
    app.use(function(req, res, next) {
        res.header(
            "Access-Control-Allow-Headers",
            "x-access-token, Origin, Content-Type, Accept"
        );
        next();
    });

    app.post("/api/auth/signin", [
        body('username').isLength({min: 1}),
        body('password').isLength({min: 1}),
    ], controller.signin);

    app.post("/api/auth/refreshtoken", [
        authJwt.verifyToken
    ], controller.refreshToken);

    app.post("/api/auth/changePassword", [
        authJwt.verifyToken,
        body('password').isLength({min: 1}),
        body('newPassword').isLength({min: 8}).withMessage('minimal is 8 character')
    ], controller.changePassword);

    app.post("/api/auth/deleteUser", [
        authJwt.verifyToken,
        authAdmin.isAdmin,
        body("userId").isLength({min:1})
    ], controller.deleteuser);

    app.post("/api/auth/isadmin",[
        authJwt.verifyToken,
        authAdmin.isAdmin
    ], controller.checkAdmin);
}
const db = require("../models");
const User = db.users;
const Role = db.role;

let isAdmin = (req, res, next) => {
    User.findOne({
        where: {
            userId: req.userId
        },
        include: {
            model: Role,
            attributes: ['id']
        }
    }).then(user => {
        if (!user) {
            return res.status(404).send({
                message: "User not found!"
            });
        }

        let isAdmin = user.roles.some(role => role.id === 3);

        if (!isAdmin) {
            return res.status(403).send({
                message: "Insufficient privilege!"
            });
        }
        next();
    }).catch(err => {
        console.error("Error while checking admin privileges:", err);
        return res.status(500).send({
            message: "Internal Server Error"
        });
    });
};

const authAdmin = {
    isAdmin: isAdmin
};

module.exports = authAdmin;

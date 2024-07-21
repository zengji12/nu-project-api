const config = require("../configs/db.config.js");

const Sequelize = require("sequelize");
const sequelize = new Sequelize(
    config.DB,
    config.USER,
    config.PASSWORD, {
    host: config.HOST,
    dialect: config.dialect,
    dialectOptions: config.dialectOptions,
    timezone: config.timezone,
    logging: false,
    define: {
        collate: config.collate,
        charset: config.charset,
    }
}
);

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;

db.users = require("./auth.model.js")(sequelize, Sequelize);
db.userKey = require("./userkeys.model.js")(sequelize, Sequelize);
db.userjunkKey = require("./userjunkkeys.model.js")(sequelize, Sequelize);
db.role = require("../models/role.model.js")(sequelize, Sequelize);
db.handshake = require("./userhandshake.model.js")(sequelize, Sequelize);

db.users.hasMany(db.userKey, { foreignKey: 'userId' });
db.userKey.belongsTo(db.users, { foreignKey: 'userId' });

db.users.hasMany(db.userjunkKey, { foreignKey: 'userId', onDelete: 'NO ACTION' });
db.userjunkKey.belongsTo(db.users, { foreignKey: 'userId', onDelete: 'NO ACTION' });

const User_Roles = sequelize.define('user_roles', {}, { timestamps: false });
db.users.belongsToMany(db.role, { through: User_Roles });
db.role.belongsToMany(db.users, { through: User_Roles });

db.users.hasMany(db.handshake, { foreignKey: 'userId', onDelete: 'NO ACTION' });
db.users.hasMany(db.handshake, { foreignKey: 'toUserId', onDelete: 'NO ACTION' });
db.handshake.belongsTo(db.users, { foreignKey: 'userId', as: 'User' });
db.handshake.belongsTo(db.users, { foreignKey: 'toUserId', as: 'ToUser' });

module.exports = db;
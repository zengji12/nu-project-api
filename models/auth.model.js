module.exports = (sequelize, Sequelize) => {
    const User = sequelize.define("users", {
        userId: {
            type: Sequelize.STRING,
            unique: true,
            primaryKey: true
        },
        fullname: {
            type: Sequelize.STRING,
            allowNull: false
        },
        username: {
            type: Sequelize.STRING,
            allowNull: false
        },
        password: {
            type: Sequelize.STRING,
            allowNull: false
        },
        alamat: {
            type: Sequelize.TEXT('medium'),
            allowNull: true
        }
    });

    return User;
};

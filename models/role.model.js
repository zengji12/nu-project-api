module.exports = (sequelize, Sequelize) => {
    const Role = sequelize.define("roles", {
        name: {
            type: Sequelize.STRING,
            unique: true
        }
    }, { timestamps: false });

    return Role;
};
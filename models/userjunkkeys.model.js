module.exports = (sequelize, Sequelize) => {
    const userJunkKey = sequelize.define("userjunkkeys", {
        id: {
            type:Sequelize.INTEGER,
            primaryKey: true,
            allowNull: true
        },
        userId: {
            type: Sequelize.STRING,
            allowNull: false
        },
        public: {
            type: Sequelize.TEXT,
            allowNull: false
        },
        private: {
            type: Sequelize.TEXT,
            allowNull: false
        },
        publicKeyIv: {
            type: Sequelize.STRING,
            allowNull: false
        },
        privateKeyIv: {
            type: Sequelize.STRING,
            allowNull: false
        },
        publicKeyAuthTag: {
            type: Sequelize.STRING, 
            allowNull: false
        },
        privateKeyAuthTag: {
            type: Sequelize.STRING, 
            allowNull: false
        },
        }, {
          timestamps: true
        });

    return userJunkKey;
};

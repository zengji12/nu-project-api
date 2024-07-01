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
        iv: {
            type: Sequelize.STRING,
            allowNull: false
        },
        authTag: {
            type: Sequelize.BLOB, 
            allowNull: false
        },
        }, {
          timestamps: true
        });

    return userJunkKey;
};

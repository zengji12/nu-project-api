module.exports = (sequelize, Sequelize) => {
    const userKey = sequelize.define("userkeys", {
        userId: {
            type: Sequelize.STRING,
            references: {
                model: 'users',
                key: 'userId'
            },
            onDelete: 'CASCADE',
            onUpdate: 'CASCADE'            
        },
        label: {
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
    });

    return userKey;
};

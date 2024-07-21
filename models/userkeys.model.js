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
        }
    });

    return userKey;
};

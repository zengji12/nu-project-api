module.exports = (sequelize, Sequelize) => {
    const userHandShake = sequelize.define("userhandshake", {
        id:{
            type:Sequelize.INTEGER,
            primaryKey: true,
            allowNull: false,
            autoIncrement: true
        }, 
        userId: {
            type: Sequelize.STRING,
            references: {
                model: 'users',
                key: 'userId'
            },
            onDelete: 'NO ACTION',
            onUpdate: 'CASCADE'            
        },
        toUserId:{
            type: Sequelize.STRING,
            references: {
                model: 'users',
                key: 'userId'
            },
            onDelete: 'NO ACTION',
            onUpdate: 'CASCADE' 
        },
        labelMe: {
            type: Sequelize.STRING,
            allowNull: true
        },
        labelYou: {
            type: Sequelize.STRING,
            allowNull: true
        },
        condition: {
            type: Sequelize.ENUM('accept', 'decline', 'waiting'),
            allowNull: false
        }
    });

    return userHandShake;
};

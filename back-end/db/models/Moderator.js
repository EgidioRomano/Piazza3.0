'use strict';

const Sequelize = require('sequelize');

/**
 * Moderator
 *
 * @param {object} sequelize Sequelize instance
 * @param {object} DataTypes Sequelize DataTypes
 *
 * @returns {object} Sequelize model
 *
 * @see http://sequelizejs.com/docs/latest/models
 */
module.exports = function (sequelize, DataTypes) {

    var Op = Sequelize.Op;

    var Moderator = sequelize.define(
        'Moderator',
        {
            id: {
                type: DataTypes.UUID,
                primaryKey: true,
                allowNull: false,
                defaultValue: sequelize.literal('(md5(((random())::text || (clock_timestamp())::text)))::uuid') // Generate ID on the DB side for now as there is no admin interface and Moderators are created manually
            },
            userId: {
                type: DataTypes.UUID,
                allowNull: false,
                comment: 'Id of the User of the Moderator',
                references: {
                    model: 'Users',
                    key: 'id'
                },
                onUpdate: 'CASCADE',
                onDelete: 'CASCADE'
            }
        },
        {
            indexes: [
                {
                    unique: true,
                    fields: ['userId']
                },
                {
                    unique: true,
                    fields: ['userId']
                }
            ]
        }
    );

    return Moderator;
};

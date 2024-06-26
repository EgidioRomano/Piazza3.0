'use strict';

module.exports = function (app) {
    const models = app.get('models');
    const db = models.sequelize;

    const logger = app.get('logger');
    const loginCheck = app.get('middleware.loginCheck');
    const asyncMiddleware = app.get('middleware.asyncMiddleware');
    const emailLib = app.get('email');
    const config = app.get('config');
    const urlLib = app.get('urlLib');
    const jwt = app.get('jwt');
    const uuid = app.get('uuid');
    const validator = app.get('validator');
    const cryptoLib = app.get('cryptoLib');
    const cosUpload = app.get('cosUpload');
    const authUser = require('./auth')(app);

    const fs = require('fs');
    const path = require('path');
    const User = models.User;
    const UserConnection = models.UserConnection;
    const UserNotificationSettings = models.UserNotificationSettings;
    const Op = db.Sequelize.Op;

    app.post('/api/users/:userId/upload', loginCheck(), asyncMiddleware(async function (req, res) {
        let user = await User.findOne({
            where: {
                id: req.user.id
            }
        });

        if (user) {
            let imageUrl;

            try {
                imageUrl = await cosUpload.upload(req, 'users', req.user.id);
            } catch (err) {
                if (err.type && (err.type === 'fileSize' || err.type === 'fileType')) {
                    return res.forbidden(err.message);
                } else {
                    throw err;
                }
            }

            await User.update(
                {
                    imageUrl: imageUrl.link
                },
                {
                    where: {
                        id: req.user.id
                    },
                    limit: 1,
                    returning: true
                }
            );

            return res.created(imageUrl);
        } else {
            res.forbidden();
        }
    }));

    /**
     * Update User info
     */
    app.put('/api/users/:userId', loginCheck(), asyncMiddleware(async function (req, res) {
        const fields = ['alias', 'email', 'imageUrl', 'preferences'];
        const data = req.body;
        if (data.password && data.newPassword) {
            fields.push('password');
        }
        let updateEmail = false;

        let user = await User.findOne({
            where: {
                id: req.user.userId
            }
        });

        data.alias = (data.alias || '').toString();

        if (!/^[a-zA-Z0-9_-]+$/.test(data.alias)) {
            return res.badRequest('Alias non valido: può contenere solo trattini, lettere e numeri.');
        }

        if (data.alias.toLowerCase() !== user.alias.toLowerCase()) {
            const aliasExists = await User.findOne({where: db.where(db.fn('lower', db.col('alias')), data.alias.toLowerCase())});
            if (aliasExists) return res.badRequest('Questo alias è già utilizzato da un altro utente.');
        }

        if (data.email && data.email !== user.email) {
            updateEmail = true;
            fields.push('emailIsVerified');
            fields.push('emailVerificationCode');
            data.emailIsVerified = false;
            data.emailVerificationCode = uuid.v4(); // Generate new emailVerificationCode
        }

        if ((user.email && updateEmail) || data.newPassword) {
            if (!data.password || user.password !== cryptoLib.getHash(data.password, 'sha256')) {
                return res.badRequest('La password fornita non è corretta.')
            }
            if (data.newPassword) {
                data.password = data.newPassword;
            }
        }

        if (Object.keys(data).indexOf('imageUrl') > -1 && !data.imageUrl && user.imageUrl) {
            const currentImageURL = new URL(user.imageUrl);
            //FIXME: No delete from DB?
            if (config.storage?.type.toLowerCase() === 's3' && currentImageURL.href.indexOf(`https://${config.storage.bucket}.s3.${config.storage.region}.amazonaws.com/users/${req.user.id}`) === 0) {
                await cosUpload.delete(currentImageURL.pathname)
            } else if (config.storage?.type.toLowerCase() === 'local' && currentImageURL.hostname === (new URL(config.url.api)).hostname) {
                const appDir = __dirname.replace('/routes/api', '/public/uploads/users');
                const baseFolder = config.storage.baseFolder || appDir;

                fs.unlinkSync(`${baseFolder}/${path.parse(currentImageURL.pathname).base}`);
            }
        }
        const results = await User.update(
            data,
            {
                where: {
                    id: req.user.userId
                },
                fields: fields,
                limit: 1,
                returning: true
            }
        );

        if (!results[1]) {
            return res.ok();
        }

        user = results[1][0];

        if (updateEmail) {
            await UserConnection.update({
                connectionData: user
            }, {
                where: {
                    connectionId: UserConnection.CONNECTION_IDS.citizenos,
                    userId: user.id
                }
            });
            const tokenData = {
                redirectSuccess: urlLib.getFe() // TODO: Misleading naming, would like to use "redirectUri" (OpenID convention) instead, but needs RAA.ee to update codebase.
            };

            const token = jwt.sign(tokenData, config.session.privateKey, {algorithm: config.session.algorithm});

            await emailLib.sendAccountVerification(user.email, user.emailVerificationCode, token);
        }

        return res.ok(user.toJSON());
    }));

    /**
     * Get User info
     *
     * Right now only supports getting info for logged in User
     */
    app.get('/api/users/:userId', loginCheck(), asyncMiddleware(async function (req, res) {
        const user = await User.findOne({
            where: {
                id: req.user.userId
            }
        });

        if (!user) {
            return res.notFound();
        }

        return res.ok(user.toJSON());
    }));

    /**
     * Get UserConnections
     *
     * Get UserConnections, that is list of methods User can use to authenticate.
     */
    app.get('/api/users/:userId/userconnections', asyncMiddleware(async function (req, res) {
        const userId = req.params.userId;
        let where;

        if (validator.isUUID(userId)) {
            const user = await User.findOne({
                where: {
                    id: userId
                },
                attributes: ['id']
            });

            if (!user) {
                return res.notFound();
            }

            where = {
                userId: userId
            }
        } else if (validator.isEmail(userId)) {
            const user = await User.findOne({
                where: {
                    email: userId
                },
                attributes: ['id']
            });

            if (!user) {
                return res.notFound();
            }

            where = {
                userId: user.id
            }
        } else {
            return res.badRequest('Invalid userId', 1);
        }

        const userConnections = await UserConnection.findAll({
            where: where,
            attributes: ['connectionId'],
            order: [[db.cast(db.col('connectionId'), 'TEXT'), 'ASC']] // Cast as we want alphabetical order, not enum order.
        });

        if (!userConnections || !userConnections.length) {
            return res.ok({
                count: 0,
                rows: []
            });
        }

        return res.ok({
            count: userConnections.length,
            rows: userConnections
        });
    }));

    app.post('/api/users/:userId/userconnections/:connection', asyncMiddleware(async function (req, res) {
        const connection = req.params.connection;
        const token = req.body.token;
        const cert = req.headers['x-ssl-client-cert'] || req.body.cert;
        const timeoutMs = req.query.timeoutMs || 5000;
        let personalInfo;

        if (!UserConnection.CONNECTION_IDS[connection]) {
            return res.badRequest('Invalid connection');
        }
        if ([UserConnection.CONNECTION_IDS.esteid, UserConnection.CONNECTION_IDS.smartid].indexOf(connection) > -1) {
            if (config.services.idCard && cert) {
                logger.error('X-SSL-Client-Cert header is not allowed when ID-card service is enabled. IF you trust your proxy, sending the X-SSL-Client-Cert, delete the services.idCard from your configuration.');
                return res.badRequest('X-SSL-Client-Cert header is not allowed when ID-card proxy service is enabled.');
            }
            if (!token && !cert) {
                logger.warn('Missing required parameter "token" OR certificate in X-SSL-Client-Cert header. One must be provided!', req.path, req.headers);
                return res.badRequest('Missing required parameter "token" OR certificate in X-SSL-Client-Cert header. One must be provided!');
            }
            if (cert || token.indexOf('.') === -1) {
                personalInfo = await authUser.getIdCardCertStatus(res, token, cert);
            } else {
                personalInfo = await authUser.getAuthReqStatus(connection, token, timeoutMs);
            }

            if (personalInfo === 'RUNNING') {
                return res.ok('Log in progress', 1);
            }

            let personId = personalInfo.pid;
            if (personalInfo.pid.indexOf('PNO') > -1) {
                personId = personId.split('-')[1];
            }
            const countryCode = personalInfo.country || personalInfo.countryCode;
            const connectionUserId = `PNO${countryCode}-${personId}`;
            await db.transaction(async function (t) {
                const userConnectionInfo = await UserConnection.findOne({
                    where: {
                        connectionId: {
                            [Op.in]: [
                                UserConnection.CONNECTION_IDS.esteid,
                                UserConnection.CONNECTION_IDS.smartid
                            ]
                        },
                        userId: req.user.id
                    },
                    order: [['createdAt', 'ASC']],
                    include: [User],
                    transaction: t
                });

                if (!userConnectionInfo) {
                    await UserConnection.create(
                        {
                            userId: req.user.id,
                            connectionId: connection,
                            connectionUserId: connectionUserId,
                            connectionData: personalInfo
                        },
                        {
                            transaction: t
                        }
                    );
                    t.afterCommit(async () => {
                        const userConnections = await UserConnection.findAll({
                            where: {
                                userId: req.user.id
                            },
                            attributes: ['connectionId'],
                            order: [[db.cast(db.col('connectionId'), 'TEXT'), 'ASC']] // Cast as we want alphabetical order, not enum order.
                        });

                        return res.ok({
                            count: userConnections.length,
                            rows: userConnections
                        });
                    });
                } else if (userConnectionInfo.connectionUserId !== connectionUserId) {
                    await authUser.clearSessionCookies(req, res);
                    t.afterCommit(() => {
                        return res.forbidden();
                    });
                }
            });
        } else {
            return res.badRequest();
        }

        const userConnections = await UserConnection.findAll({
            where: {
                userId: req.user.id
            },
            attributes: ['connectionId'],
            order: [[db.cast(db.col('connectionId'), 'TEXT'), 'ASC']] // Cast as we want alphabetical order, not enum order.
        });

        return res.ok({
            count: userConnections.length,
            rows: userConnections
        });
    }));


    /**
     * Read User preferences
    */
    app.get('/api/users/:userId/notifications', loginCheck(), asyncMiddleware(async function (req, res) {
        const userId = req.user.userId;
        const type = req.params.type || null;

        const preferences = await UserNotificationSettings
            .findAll({
                where: {
                    userId,
                    type
                }
            });

        return res.ok({
            preferences
        });
    }));

};

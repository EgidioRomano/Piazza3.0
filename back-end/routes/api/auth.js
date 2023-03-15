'use strict';

module.exports = function (app) {

    const logger = app.get('logger');
    const cryptoLib = app.get('cryptoLib');
    const loginCheck = app.get('middleware.loginCheck');
    const asyncMiddleware = app.get('middleware.asyncMiddleware');
    const emailLib = app.get('email');
    const validator = app.get('validator');
    const util = app.get('util');
    const config = app.get('config');
    const models = app.get('models');
    const db = models.sequelize;
    const Op = db.Sequelize.Op;
    const cosActivities = app.get('cosActivities');
    const jwt = app.get('jwt');
    const querystring = app.get('querystring');
    const urlLib = app.get('urlLib');
    const url = app.get('url');

    const speedLimiter = app.get('speedLimiter');
    const rateLimiter = app.get('rateLimiter');
    const expressRateLimitInput = app.get('middleware.expressRateLimitInput');

    const User = models.User;
    const UserConnection = models.UserConnection;
    const TokenRevocation = models.TokenRevocation;


    app.post('/api/auth/signup', asyncMiddleware(async function (req, res) {
        const email = req.body.email || ''; // HACK: Sequelize validate() is not run if value is "null". Also cannot use allowNull: false as I don' want constraint in DB. https://github.com/sequelize/sequelize/issues/2643
        const password = req.body.password || ''; // HACK: Sequelize validate() is not run if value is "null". Also cannot use allowNull: false as I don' want constraint in DB. https://github.com/sequelize/sequelize/issues/2643
        const name = req.body.name || util.emailToDisplayName(req.body.email);
        const company = req.body.company;
        const language = req.body.language;
        const redirectSuccess = req.body.redirectSuccess || urlLib.getFe();
        const preferences = req.body.preferences;
        const termsVersion = req.body.termsVersion;

        let created = false;

        let user = await User
            .findOne({
                where: db.where(db.fn('lower', db.col('email')), db.fn('lower', email)),
                include: [UserConnection]
            });

        if (user) {
            // IF password is null, the User was created through an invite. We allow an User to claim the account.
            // Check the source so that User cannot claim accounts created with Google/FB etc - https://github.com/citizenos/citizenos-fe/issues/773
            if (!user.password && user.source === User.SOURCES.citizenos && !user.UserConnections.length) {
                user.password = password;
                user.name = name || user.name;
                user.company = company || user.company;
                user.language = language || user.language;
                await user.save({fields: ['password', 'name', 'company', 'language']});
            } else {
                // Email address is already in use.
                return res.ok(`Check your email ${email} to verify your account.`);
            }
        } else {
            await db.transaction(async function (t) {
                [user, created] = await User
                    .findOrCreate({
                        where: db.where(db.fn('lower', db.col('email')), db.fn('lower', email)), // Well, this will allow user to log in either using User and pass or just Google.. I think it's ok..
                        defaults: {
                            name,
                            email,
                            password,
                            company,
                            source: User.SOURCES.citizenos,
                            language,
                            termsVersion,
                            preferences
                        },
                        transaction: t
                    });

                if (created) {
                    logger.info('Created a new user', user.id);
                    await cosActivities.createActivity(
                        user,
                        null,
                        {
                            type: 'User',
                            id: user.id,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );
                }

                const uc = await UserConnection
                    .create({
                        userId: user.id,
                        connectionId: UserConnection.CONNECTION_IDS.citizenos,
                        connectionUserId: user.id,
                        connectionData: user
                    }, {
                        transaction: t
                    });

                return cosActivities.addActivity(
                    uc,
                    {
                        type: 'User',
                        id: user.id,
                        ip: req.ip
                    },
                    null,
                    user,
                    req.method + ' ' + req.path,
                    t
                );
            });
        }

        if (user) {
            if (user.emailIsVerified) {
                setAuthCookie(req, res, user.id);

                return res.ok({redirectSuccess});
            } else {
                // Store redirect url in the token so that /api/auth/verify/:code could redirect to the url late
                const tokenData = {
                    redirectSuccess // TODO: Misleading naming, would like to use "redirectUri" (OpenID convention) instead, but needs RAA.ee to update codebase.
                };

                const token = jwt.sign(tokenData, config.session.privateKey, {algorithm: config.session.algorithm});
                await emailLib.sendAccountVerification(user.email, user.emailVerificationCode, token);

                return res.ok(`Check your email ${user.email} to verify your account.`, user.toJSON());
            }
        } else {
            return res.ok(`Check your email ${user.email} to verify your account.`);
        }
    }));


    const setAuthCookie = function (req, res, userId) {
        const token = TokenRevocation.build();
        const authToken = jwt.sign({
            userId,
            tokenId: token.tokenId,
            scope: 'all'
        }, config.session.privateKey, {
            expiresIn: config.session.cookie.maxAge,
            algorithm: config.session.algorithm
        });
        res.cookie(config.session.name, authToken, Object.assign({secure: req.secure}, config.session.cookie));
    };

    const clearSessionCookies = async function (req, res) {
        let token;
        const cookieAuthorization = req.cookies[config.session.name];

        if (cookieAuthorization) {
            token = cookieAuthorization;
        }

        const tokenData = jwt.verify(token, config.session.publicKey, {algorithms: [config.session.algorithm]});

        await TokenRevocation.create({
            tokenId: req.user.tokenId,
            expiresAt: new Date(tokenData.exp * 1000)
        });

        res.clearCookie(config.session.name, {
            path: config.session.cookie.path,
            domain: config.session.cookie.domain
        });
    };

    /**
     * Login
     */
    app.post('/api/auth/login', rateLimiter(50), speedLimiter(15), expressRateLimitInput(['body.email'], 15 * 60 * 1000, 10), async function (req, res) {
        const email = (req.body.email || '').toString();
        const password = (req.body.password || '').toString();

        if (email === '') {
            return;
        }
        else if (!validator.isEmail(email)) {
            return res.badRequest("L'indirizzo e-mail non è valido.", 40001);
        }
        
        await new Promise(r => setTimeout(r, Math.floor(Math.random() * 1000))); // to prevent time-based user enumeration

        const user = await User.findOne({where: db.where(db.fn('lower', db.col('email')), db.fn('lower', email))});

        if (user && user.password === cryptoLib.getHash(password, 'sha256')) {
            const userData = user.toJSON();

            if (!user.emailIsVerified) {
                await emailLib.sendAccountVerification(user.email, user.emailVerificationCode);

                return res.badRequest("La verifica dell'account non è stata ancora completata. Si prega di controllare la casella di posta elettronica.");
            }

            setAuthCookie(req, res, user.id);

            return res.ok(userData);
        } else {
            return res.badRequest("Credenziali non valide.", 40001);
        }        
    });


    app.post('/api/auth/logout', loginCheck(), asyncMiddleware(async function (req, res) {
        await clearSessionCookies(req, res);

        return res.ok();
    }));


    app.post('/api/auth/password', loginCheck(), asyncMiddleware(async function (req, res) {
        const currentPassword = req.body.currentPassword;
        const newPassword = req.body.newPassword;

        const user = await User
            .findOne({
                where: {
                    id: req.user.userId
                }
            });

        if (!user || user.password !== cryptoLib.getHash(currentPassword, 'sha256')) {
            return res.badRequest('Indirizzo e-mail o password non validi.');
        }

        user.password = newPassword;

        await user.save({fields: ['password']});

        return res.ok();
    }));


    app.post('/api/auth/password/reset/send', rateLimiter(50), speedLimiter(15), expressRateLimitInput(['body.email'], 15 * 60 * 1000, 5), asyncMiddleware(async function (req, res) {
        const email = req.body.email;

        if (!email || !validator.isEmail(email.toString())) {
            return res.badRequest({email: "L'indirizzo e-mail non è valido."});
        }

        await new Promise(r => setTimeout(r, Math.floor(Math.random() * 1000))); // to prevent time-based user enumeration

        const user = await User.findOne({where: db.where(db.fn('lower', db.col('email')), db.fn('lower', email))});

        if (!user) {
            return res.ok('Controlla la tua casella di posta elettronica per completare il recupero della password.');
        }

        user.passwordResetCode = true; // Model will generate new code

        await user.save({fields: ['passwordResetCode']});

        await emailLib.sendPasswordReset(user.email, user.passwordResetCode);

        return res.ok('Controlla la tua casella di posta elettronica per completare il recupero della password.');
    }));


    app.post('/api/auth/password/reset', asyncMiddleware(async function (req, res) {
        const email = req.body.email;
        const password = req.body.password;
        const passwordResetCode = req.body.passwordResetCode;

        await new Promise(r => setTimeout(r, Math.floor(Math.random() * 1000))); // to prevent time-based user enumeration

        const user = await User.findOne({
            where: {
                [Op.and]: [
                    db.where(db.fn('lower', db.col('email')), db.fn('lower', email)),
                    db.where(db.col('passwordResetCode'), passwordResetCode)
                ]
            }
        });

        // !user.passwordResetCode avoids the situation where passwordResetCode has not been sent (null), but user posts null to API
        if (!user || !user.passwordResetCode) {
            return res.badRequest("L'indirizzo e-mail, la password o il codice di reset non sono validi.");
        }

        user.password = password; // Hash is created by the model hooks
        user.passwordResetCode = true; // Model will generate new code so that old code cannot be used again - https://github.com/citizenos/citizenos-api/issues/68

        await user.save({fields: ['password', 'passwordResetCode']});
        //TODO: Logout all existing sessions for the User!
        return res.ok();
    }));


    /**
     * Get logged in User info
     *
     * @deprecated Use GET /api/users/self instead.
     */
    app.get('/api/auth/status', loginCheck(), asyncMiddleware(async function (req, res) {
        const user = await User.findOne({
            where: {
                id: req.user.userId
            }
        });

        if (!user) {
            await clearSessionCookies(req, res);

            return res.notFound();
        }

        const userData = user.toJSON();
        userData.preferences = user.dataValues.preferences;

        return res.ok(userData);
    }));


    return {
        clearSessionCookies: clearSessionCookies
    }
};

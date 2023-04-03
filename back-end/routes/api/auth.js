'use strict';

module.exports = function (app) {

    const cryptoLib = app.get('cryptoLib');
    const loginCheck = app.get('middleware.loginCheck');
    const asyncMiddleware = app.get('middleware.asyncMiddleware');
    const emailLib = app.get('email');
    const validator = app.get('validator');
    const config = app.get('config');
    const models = app.get('models');
    const db = models.sequelize;
    const Op = db.Sequelize.Op;
    const jwt = app.get('jwt');

    const speedLimiter = app.get('speedLimiter');
    const rateLimiter = app.get('rateLimiter');
    const expressRateLimitInput = app.get('middleware.expressRateLimitInput');

    const User = models.User;
    const TokenRevocation = models.TokenRevocation;

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

        if (!email.length || !validator.isEmail(email)) {
            return res.badRequest("L'indirizzo e-mail fornito non è valido.", 1);
        }
        
        await new Promise(r => setTimeout(r, Math.floor(Math.random() * 1000))); // to prevent time-based user enumeration

        const user = await User.findOne({where: db.where(db.fn('lower', db.col('email')), db.fn('lower', email))});

        if (user && user.password === cryptoLib.getHash(password, 'sha256')) {
            const userData = user.toJSON();

            if (!user.emailIsVerified) {
                await emailLib.sendAccountVerification(user.email, user.emailVerificationCode);

                return res.badRequest("La verifica dell'indirizzo e-mail non è stata ancora completata. Si prega di controllare la casella di posta elettronica.", 2);
            }

            setAuthCookie(req, res, user.id);

            return res.ok(userData);
        } else {
            return res.badRequest("Credenziali non valide.", 3);
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
        const email = (req.body.email || '').toString();

        if (!email.length || !validator.isEmail(email)) {
            return res.badRequest({email: "L'indirizzo e-mail fornito non è valido."});
        }

        await new Promise(r => setTimeout(r, Math.floor(Math.random() * 1000))); // to prevent time-based user enumeration

        const user = await User.findOne({where: db.where(db.fn('lower', db.col('email')), db.fn('lower', email))});

        if (user) {
            user.passwordResetCode = true; // Model will generate new code

            await user.save({fields: ['passwordResetCode']});
    
            await emailLib.sendPasswordReset(user.email, user.passwordResetCode);
        }

        return res.ok('Controlla la tua casella di posta elettronica per completare il reset della password.');
    }));


    app.post('/api/auth/password/reset', rateLimiter(50), speedLimiter(15), expressRateLimitInput(['body.email'], 15 * 60 * 1000, 5), asyncMiddleware(async function (req, res) {
        const email = (req.body.email || '').toString();
        const password = (req.body.password || '').toString();
        const passwordResetCode = (req.body.passwordResetCode || '').toString();

        if (!email.length || !validator.isEmail(email)) {
            return res.badRequest("L'indirizzo e-mail fornito non è valido.", 1);
        }
        else if (!validator.isUUID(passwordResetCode)) {
            return res.badRequest("Il codice di reset fornito non è valido.", 2);
        }

        await new Promise(r => setTimeout(r, Math.floor(Math.random() * 1000))); // to prevent time-based user enumeration

        const user = await User.findOne({
            where: {
                [Op.and]: [
                    db.where(db.fn('lower', db.col('email')), db.fn('lower', email)),
                    db.where(db.col('passwordResetCode'), passwordResetCode)
                ]
            }
        });

        if (!user) {
            return res.badRequest("L'indirizzo e-mail o il codice di reset non sono validi.", 3);
        }

        user.password = password; // Hash is created by the model hooks
        user.passwordResetCode = true; // Model will generate new code so that old code cannot be used again - https://github.com/citizenos/citizenos-api/issues/68

        await user.save({fields: ['password', 'passwordResetCode']});
        //TODO: Logout all existing sessions for the User!
        return res.ok();
    }));


    /**
     * Get logged in User info
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
        userData.isSuperAdmin = req.user.isSuperAdmin;

        return res.ok(userData);
    }));


    return {
        clearSessionCookies: clearSessionCookies
    }
};

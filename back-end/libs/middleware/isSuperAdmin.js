'use strict';

/**
 * Middleware to perform super admin check
 *
 * @returns {function} Express middleware function
 */
module.exports = function () {
    return function (req, res, next) {
        if (!req.user || !req.user.userId) {
            return res.unauthorised();
        }

        var admins = req.app.get('config').admins;

        if (admins.indexOf(req.user.userId) < 0) {
            return res.unauthorised('Accesso negato. Non sei un amministratore.');
        }

        return next();
    };
};

'use strict';

/**
 * Middleware to perform super admin check
 *
 * @returns {function} Express middleware function
 */
module.exports = function () {
    return function (req, res, next) {
        if (!req.user || !req.user.isSuperAdmin) {
            return res.unauthorised('Accesso negato. Non sei un amministratore.');
        }

        return next();
    };
};

'use strict';
import * as angular from 'angular';

export class Auth {
    private user = {
        loggedIn: false,
        isSuperAdmin: false,
        isLoading: true
    };

    private defaultSuccess = (response) => {
        return response.data;
    };

    private defaultError = (response) => {
        return this.$q.reject(response);
    };

    constructor (private $http, private $q, private $log, private sLocation, private cosConfig) {}

    signUp (email, password, name, alias, redirectSuccess, preferences) {
        const data = {
            email: email,
            password: password,
            name: name,
            alias: alias,
            redirectSuccess: redirectSuccess,
            preferences: preferences
        };

        const path = this.sLocation.getAbsoluteUrlApi('/api/auth/signup');

        return this.$http.post(path, data).then(this.defaultSuccess,this.defaultError);
    };

    login (email, password) {
        const data = {
            email: email,
            password: password
        };

        const success = (response) => {
            this.user.loggedIn = true;
            angular.extend(this.user, response.data.data);
        };

        const path = this.sLocation.getAbsoluteUrlApi('/api/auth/login');

        return this.$http.post(path, data).then(success, this.defaultError);
    };

    logout () {
        const success = (response) => {
            // Delete all user data except login status.
            // Cant reference a new object here as Angular looses bindings.
            angular.forEach(this.user, (value, key) => {
                if (key !== 'loggedIn') {
                    delete this.user[key];
                }
            });
            this.user.loggedIn = false;

            return response;
        };

        const pathLogoutEtherpad = this.sLocation.getAbsoluteUrlEtherpad('/ep_auth_citizenos/logout');
        const pathLogoutAPI = this.sLocation.getAbsoluteUrlApi('/api/auth/logout');

        return this.$http
            .get(pathLogoutEtherpad) // Call Etherpad logout - https://github.com/citizenos/citizenos-fe/issues/676
            .then((success, err) => {
                if (err) throw err;
                return this.$http.post(pathLogoutAPI);
            })
            .then(success, this.defaultError);
    };

    status () {
        const success = (response) => {
            this.$log.debug('status', response);
            angular.extend(this.user, response.data.data);
            this.user.loggedIn = true;
            this.user.isLoading = false;

            return response.data.data;
        };

        const error = (response) => {
            this.user.isLoading = false;

            return this.defaultError(response);
        };

        const path = this.sLocation.getAbsoluteUrlApi('/api/auth/status');
        return this.$http.get(path).then(success, error);
    };

    passwordResetSend (email) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/auth/password/reset/send');
        return this.$http.post(path, {email: email}).then(this.defaultSuccess, this.defaultError);
    };

    passwordReset (email, password, passwordResetCode) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/auth/password/reset');
        return this.$http.post(path, {
            email: email,
            password: password,
            passwordResetCode: passwordResetCode
        }).then(this.defaultSuccess, this.defaultError);
    };

    getUrlPrefix () {
        if (this.user.loggedIn) {
            return 'users';
        }
        return null;
    };

    getUrlUserId () {
        if (this.user.loggedIn) {
            return 'self';
        }
        return null;
    };
}
angular
    .module('citizenos')
    .service('sAuth', ['$http', '$q', '$log', 'sLocation', 'cosConfig', Auth]);

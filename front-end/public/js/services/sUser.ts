'use strict';
import * as angular from 'angular';
export class User {
    // Map UserConnections.connectionId to authentication method
    private USER_CONNECTION_IDS_TO_AUTH_METHOD_MAP = {
        citizenos: 'citizenos'
    };
    private defaultSuccess = (response) => {
        return response.data.data;
    };

    private defaultError = (response) => {
        return this.$q.reject(response);
    };

    constructor (private $http, private $q, private sLocation) {}

    update (name?, email?, password?, birthday?, imageUrl?, preferences?, language?, newPassword?) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/self');
        const userData = {
            name: null,
            password: null,
            email: email,
            birthday: birthday,
            imageUrl: imageUrl,
            language: language,
            preferences: preferences,
            newPassword: newPassword
        };

        if (name) {
            userData.name = name;
        }

        if (password) {
            userData.password = password;
        }

        if (!newPassword) {
            userData.newPassword = newPassword;
        }

        return this.$http.put(path, userData);
    };

    updateLanguage (language) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/self');

        return this.$http.put(path, {language: language});
    };

    deleteUser () {
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/self');

        return this.$http.delete(path);
    };

    listUserConnections (userId) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/:userId/userconnections', {userId: userId});

        return this.$http.get(path).then(this.defaultSuccess, this.defaultError);
    };

    addUserConnection (userId, connection, token?, cert?, redirectSuccess?) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/:userId/userconnections/:connection', {userId: userId, connection: connection});

        return this.$http.post(path, {token: token, cert: cert, redirectSuccess: redirectSuccess}).then(this.defaultSuccess, this.defaultError);
    }

}
angular
    .module('citizenos')
    .service('sUser', ['$http', '$q', 'sLocation', User]);

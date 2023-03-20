'use strict';
import * as angular from 'angular';

let loginFormComponent = {
    selector: 'loginForm',
    templateUrl: '/views/components/account/login.html',
    bindings: {
        email: '@?'
    },
    controller: ['$log', '$state', '$stateParams', '$window', '$document', '$interval', 'cosConfig', 'ngDialog', 'sAuth', 'sLocation', 'sUser', 'sNotification', 'AppService', class LoginFormController {
        private email;
        public authMethodsAvailable;
        public isFormEmailProvided;
        private linkRegister;
        private form;
        private errors;

        constructor(private $log, private $state, private $stateParams, private $window, private $document, private $interval, private cosConfig, private ngDialog, private sAuth, private sLocation, private sUser, private sNotification, private app) {
            if ($stateParams.email) {
                this.email = $stateParams.email;
            }
            this.authMethodsAvailable = angular.extend({}, cosConfig.features.authentication);
            console.log(cosConfig.features.authentication)
            if ($stateParams.userId) {
                sUser
                    .listUserConnections($stateParams.userId)
                    .then((res) => {
                        Object.keys(this.authMethodsAvailable).forEach((method) => {
                            this.authMethodsAvailable[method] = false;
                            res.rows.forEach((availableMethod) => {
                                if (availableMethod.connectionId === method) {
                                    this.authMethodsAvailable[method] = true;
                                }
                            })
                        });
                    }, (err) => {
                        // If the UserConnection fetch fails, it does not matter, we just don't filter authentication methods
                        $log.warn('Unable to fetch UserConnections for User', err);
                        return;
                    });
            }

            this.isFormEmailProvided = this.email;
            this.linkRegister = sLocation.getAbsoluteUrl('/account/signup');

            this.init();
            // UserConnections to know which auth methods to show - https://github.com/citizenos/citizenos-fe/issues/657
            const userConnections = this.$stateParams ? this.$stateParams.userConnections : null;
            if (userConnections) {
                let userAuthMethods = [];

                if (userConnections.rows.length) {
                    // Check out from the UserConnection.connectionId map which authentication methods apply
                    userConnections.rows.forEach((val) => {
                        userAuthMethods = userAuthMethods.concat(sUser.USER_CONNECTION_IDS_TO_AUTH_METHOD_MAP[val.connectionId]);
                    });

                    // Reduce to unique values
                    userAuthMethods = userAuthMethods.filter((val, i, res) => {
                        return res.indexOf(val) === i;
                    });
                } else {
                    // IF no UserConnections is returned, that is a for an unregistered user, show 'citizenos' auth method.
                    userAuthMethods.push('citizenos');
                }

                // Initially the authMethods that are configured are all available, modify the list so that only those User has available are enabled
                Object.keys(this.authMethodsAvailable).forEach((val) => {
                    this.authMethodsAvailable[val] = userAuthMethods.indexOf(val) > -1;
                });
            }
        }

        init() {
            this.form = {
                email: this.isFormEmailProvided ? this.email : null,
                password: null
            };
            this.app.showNav = false; // Hide mobile navigation when login flow is started
        }

        popupCenter(url, title, w, h) {
            const userAgent = navigator.userAgent,
                mobile = () => {
                    return /\b(iPhone|iP[ao]d)/.test(userAgent) ||
                        /\b(iP[ao]d)/.test(userAgent) ||
                        /Android/i.test(userAgent) ||
                        /Mobile/i.test(userAgent);
                },
                screenX = typeof window.screenX != 'undefined' ? window.screenX : window.screenLeft,
                screenY = typeof window.screenY != 'undefined' ? window.screenY : window.screenTop,
                outerWidth = typeof window.outerWidth != 'undefined' ? window.outerWidth : document.documentElement.clientWidth,
                outerHeight = typeof window.outerHeight != 'undefined' ? window.outerHeight : document.documentElement.clientHeight - 22,
                targetWidth = mobile() ? null : w,
                targetHeight = mobile() ? null : h,
                V = screenX < 0 ? window.screen.width + screenX : screenX,
                left = Number(V) + Number(outerWidth - targetWidth) / 2;
            const right = screenY + (outerHeight - targetHeight) / 2.5;
            const features = [];
            if (targetWidth !== null) {
                features.push('width=' + targetWidth);
            }
            if (targetHeight !== null) {
                features.push('height=' + targetHeight);
            }
            features.push('left=' + left);
            features.push('top=' + right);
            features.push('scrollbars=1');

            const newWindow = window.open(url, title, features.join(','));

            if (window.focus) {
                newWindow.focus();
            }

            return newWindow;
        };

        doLogin() {
            this.$log.debug('LoginFormCtrl.doLogin()');

            this.errors = null;
            const success = (response) => {
                if (this.$stateParams.redirectSuccess) {
                    this.$window.location.href = this.$stateParams.redirectSuccess;
                } else {
                    this.$window.location = '/';
                }
            };

            const error = (response) => {
                const status = response.data.status;
                console.log('ERROR', status);

                switch (status.code) {
                    case 40001: // Account does not exist
                        this.sNotification.removeAll();
                        this.errors = { accoundDoesNotExist: true };
                        break;
                    default:
                        this.errors = response.data.errors;
                }
            };

            this.sAuth
                .login(this.form.email, this.form.password)
                .then(success, error);
        };

        /**
         * Login with Estonian ID-Card
         */
        doLoginEsteId() {
            this.ngDialog
                .open({
                    template: '<login-est-eid></login-est-eid>',
                    plain: true
                });
        };

        /**
         * Login with Smart-ID
         */
        doLoginSmartId() {
            this.ngDialog
                .open({
                    template: '<login-smart-id></login-smart-id>',
                    plain: true
                });
        };

        /**
         * Password reset
         */
        doResetPassword() {
            this.ngDialog
                .open({
                    template: '<password-forgot></password-forgot>',
                    plain: true
                });
        };

    }]
};
angular
    .module('citizenos')
    .component(loginFormComponent.selector, loginFormComponent);

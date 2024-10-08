import * as angular from 'angular';
export class Topic {
    private STATUSES = {
        inProgress: 'inProgress', // Being worked on
        voting: 'voting', // Is being voted which means the Topic is locked and cannot be edited.
        followUp: 'followUp' // Done editing Topic and executing on the follow up plan.
    };

    private VISIBILITY = {
        public: 'public', // Everyone has read-only on the Topic.  Pops up in the searches..
        private: 'private' // No-one can see except collaborators
    };

    private LEVELS = {
        read: 'read',
        edit: 'edit',
        admin: 'admin'
    };

    private CATEGORIES = {
        environment: 'environment',
        culture: 'culture',
        economy: 'economy',
        family: 'family',
        socialinclusion: 'socialinclusion',
        urbandecorum: 'urbandecorum',
        health: 'health',
        school: 'school',
        security: 'security',
        sport: 'sport',
        mobility: 'mobility',
        technology: 'technology',
        tourism: 'tourism',
        other: 'other'
    };

    private REPORT_TYPES = {
        abuse: 'abuse', // is abusive or insulting
        obscene: 'obscene', // contains obscene language
        spam: 'spam', // contains spam or is unrelated to topic
        hate: 'hate', // contains hate speech
        netiquette: 'netiquette', // infringes (n)etiquette
        duplicate: 'duplicate' // duplicate
    };

    private CATEGORIES_COUNT_MAX = 3; // Maximum of 3 categories allowed at the time.

    getUrlPrefix () {
        const prefix = this.sAuth.getUrlPrefix();
        if (!prefix) {
            return '';
        }

        return `/${prefix}`;
    };

    getUrlUser () {
        const userId = this.sAuth.getUrlUserId();
        if (!userId) {
            return '';
        }

        return `/${userId}`;
    };

    constructor(private $http, private sAuth, private sLocation, private sUser, private TopicVote, private ngDialog, private $state, private $stateParams) {
    }

    get(id, params?: any) {
        let path = this.sLocation.getAbsoluteUrlApi('/api/:prefix/:userId/topics/:topicId', {topicId: id})
            .replace('/:prefix', this.getUrlPrefix())
            .replace('/:userId', this.getUrlUser());

        return this.$http.get(path, {params})
            .then((res) => {
                const topic = res.data.data;

                if ((topic.vote && topic.vote.id) || topic.voteId) {
                    if (!topic.vote) {
                        this.TopicVote.get({
                            voteId: topic.voteId,
                            topicId: topic.id
                        }).then((vote) => {
                            topic.vote = vote;
                        });
                    }
                }
                return topic;
            });
    }

    getByToken (data) {
        let path = this.sLocation.getAbsoluteUrlApi('/api/topics/join/:token', {token: data.token || data})

        return this.$http.get(path, data)
            .then((res) => {
                return res.data.data
            });
    };

    query(params: any) {
        let path = this.sLocation.getAbsoluteUrlApi('/api/:prefix/:userId/topics', params)
            .replace('/:prefix', this.getUrlPrefix())
            .replace('/:userId', this.getUrlUser());

        return this.$http.get(path, { params })
            .then((res) => {
                res.data.data.rows.forEach((topic) => {
                    if ((topic.vote && topic.vote.id) || topic.voteId) {
                        if (!topic.vote) {
                            this.TopicVote.get({
                                topicId: topic.id,
                                voteId: topic.voteId})
                            .then((vote) => {
                                topic.vote = vote;
                            });
                        }
                    }
                });

                return res.data.data;
        });
    };

    queryPublic(params: any) {
        let path = this.sLocation.getAbsoluteUrlApi('/api/topics', params);

        return this.$http.get(path, { params })
            .then((res) => {
                return res.data.data;
        });
    };

    save(data: any) {
        let path = this.sLocation.getAbsoluteUrlApi('/api/:prefix/:userId/topics')
            .replace('/:prefix', this.getUrlPrefix())
            .replace('/:userId', this.getUrlUser());

        return this.$http.post(path, data)
        .then((res) => {
            return res.data.data
        });
    }

    update(data: any) {
        const updateFields = ['visibility', 'status', 'categories', 'endsAt', 'myGroup'];
        const sendData = {};

        updateFields.forEach(function (field) {
            if (field in data) {
                sendData[field] = data[field];
            }
        });

        const path = this.sLocation.getAbsoluteUrlApi('/api/:prefix/:userId/topics/:topicId', {topicId: data.id || data.topicId})
            .replace('/:prefix', this.getUrlPrefix())
            .replace('/:userId', this.getUrlUser());

        return this.$http.put(path, sendData)
            .then((res) => {
                return res.data.data
            });
    }

    patch (data: any) {
        const updateFields = ['visibility', 'status', 'categories', 'endsAt'];
        const sendData = {};

        updateFields.forEach(function (field) {
            if (field in data) {
                sendData[field] = data[field];
            }
        });

        const path = this.sLocation.getAbsoluteUrlApi('/api/:prefix/:userId/topics/:topicId', {topicId: data.id || data.topicId})
            .replace('/:prefix', this.getUrlPrefix())
            .replace('/:userId', this.getUrlUser());

            return this.$http.patch(path, sendData)
                .then((res) => {
                    return res.data.data
                });
    }

    delete(data: any) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/self/topics/:topicId', {topicId: data.id || data.topicId});

        return this.$http.delete(path)
            .then((res) => {return res.data.data});
    }

    join (data) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/topics/join/:token', {token: data.token || data});

        return this.$http.post(path).then((res) => {
            return res.data;
        });
    }

    duplicate (data) {
        if (!data.topicId) data.topicId = data.id;
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/self/topics/:topicId/duplicate', data);

        return this.$http
            .get(path)
            .then((res) => {
                return res.data.data;
            });
    };

    addToPinned (topicId) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/self/topics/:topicId/pin', {topicId: topicId});

        return this.$http.post(path)
            .then((res) => {
                return res.data;
            });
    }

    removeFromPinned (topicId) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/self/topics/:topicId/pin', {topicId: topicId});

        return this.$http.delete(path)
            .then((res) => {
                return res.data;
            });
    }

    getInlineComments (topicId) {
        const path = this.sLocation.getAbsoluteUrlApi('/api/users/self/topics/:topicId/inlinecomments', {topicId: topicId});

        return this.$http.get(path)
            .then((res) => {
                return res.data.data;
            });
    }

    publishTopic (topic, myGroup) {
        this.ngDialog
            .openConfirm({
                template: '/views/modals/topic_publish_confirm.html'
            })
            .then(() => {
                return this.update({
                    id: topic.id,
                    visibility: 'public',
                    myGroup: myGroup
                });
            })
            .then(() => {
                const stateParams = angular.extend({}, this.$stateParams, {
                    topicId: topic.id,
                    commentId: null
                });
                this.$state.go(
                    'topics/view',
                    stateParams,
                    {
                        reload: true
                    }
                );
            }, angular.noop);
    }

    changeState (topic, state, stateSuccess) {
        const templates = {
            followUp: '/views/modals/topic_send_to_followUp_confirm.html',
            vote: '/views/modals/topic_send_to_vote_confirm.html',
            closed: '/views/modals/topic_close_confirm.html'
        };
        const nextStates = {
            followUp: 'topics/view/followUp',
            vote: 'topics/view/votes/view',
            closed: 'topics/view'
        };

        this.ngDialog
            .openConfirm({
                template: templates[state]
            })
            .then(() => {
                if (state === 'vote' && !topic.voteId && !topic.vote) {
                    this.$state.go('topics/view/votes/create', {
                        topicId: topic.id,
                        commentId: null
                    }, {reload: true});
                    return;
                }

                return this.patch({
                    id: topic.id,
                    status: this.STATUSES[state]
                });
            })
            .then(() => {
                const stateNext = stateSuccess || nextStates[state];
                const stateParams = angular.extend({}, this.$stateParams, {
                    editMode: null,
                    commentId: null
                });
                this.$state.go(
                    stateNext,
                    stateParams,
                    {
                        reload: true
                    }
                );
            }, angular.noop);
    }

    // Methods
    isPrivate (topic) {
        return topic && topic.visibility === this.VISIBILITY.private;
    };

    canUpdate (topic) {
        return (topic && topic.permission && topic.permission.level === this.LEVELS.admin);
    };

    /**
     * Can one edit Topics settings and possibly description (content)?
     * Use canEditDescription() if you only need to check if content can be edited.
     *
     * @returns {boolean}
     *
     */
    canEdit (topic) {
        return (topic && [this.LEVELS.admin, this.LEVELS.edit].indexOf(topic.permission.level) > -1);
    };

    /**
     * Can one edit Topics description (content)?
     *
     * @returns {boolean}
     *
     */
    canEditDescription (topic) {
        return this.canEdit(topic) && topic.status === this.STATUSES.inProgress;
    };

    canDelete (topic) {
        return (topic && topic.permission.level === this.LEVELS.admin);
    };

    canVote (topic) {
        return (topic.vote && topic.permission.level !== 'none ' && topic.status === this.STATUSES.voting);
    };

    canDelegate (topic) {
        return (this.canVote(topic) && topic.vote.delegationIsAllowed === true);
    };

    canSendToFollowUp (topic) {
        return this.canUpdate(topic) && topic.vote && topic.vote.id && topic.status !== this.STATUSES.followUp;
    };

    canSendToVote (topic) {
        return this.canUpdate(topic) && [this.STATUSES.voting].indexOf(topic.status) < 0;
    };

    canLeave () {
        return this.sAuth.user.loggedIn;
    };

    hasVoteEnded (topic) {
        if ([this.STATUSES.followUp].indexOf(topic.status) > -1) {
            return true;
        }

        return topic.vote && topic.vote.endsAt && new Date() > new Date(topic.vote.endsAt);
    };

    // TopicVote has ended due to expiry!
    hasVoteEndedExpired (topic) {
        return [this.STATUSES.followUp].indexOf(topic.status) < 0 && topic.vote && topic.vote.endsAt && new Date() > new Date(topic.vote.endsAt);
    };

    togglePin (topic) {
        if (!topic.pinned) {
            return this.addToPinned(topic.id)
                .then(() => {
                    topic.pinned = true;
                });
        } else {
            return this.removeFromPinned(topic.id)
                .then(() => {
                    topic.pinned = false;
                })
        }
    };
}

angular
  .module("citizenos")
  .service("Topic", ['$http', 'sAuth', 'sLocation', 'sUser', 'TopicVote', 'ngDialog', '$state', '$stateParams', Topic]);

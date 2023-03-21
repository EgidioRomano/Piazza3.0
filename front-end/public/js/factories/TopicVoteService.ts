import * as angular from 'angular';

export class TopicVoteService {
    public countTotal = 0;
    public isLoading = false;
    private isSaving = false;
    private topicId = null;
    private voteId = null;
    private options = [];
    public isLoadingIdCard = false;
    public challengeID = null;
    private pid;
    private phoneNumber;
    private countryCode;

    constructor(private $window, private $state, private TopicVote, private $q, private $log, private $timeout, private sAuth, private sNotification) {}

};

angular
  .module("citizenos")
  .service("TopicVoteService", ['$window', '$state', 'TopicVote', '$q', '$log', '$timeout', 'sAuth', 'sNotification', TopicVoteService]);

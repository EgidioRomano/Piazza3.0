'use strict';

/**
 * Topic API-s (/api/../topics/..)
 */

module.exports = function (app) {
    const config = app.get('config');
    const logger = app.get('logger');
    const models = app.get('models');
    const db = models.sequelize;
    const Sequelize = require('sequelize');
    const { injectReplacements } = require('sequelize/lib/utils/sql');
    const Op = db.Sequelize.Op;
    const _ = app.get('lodash');
    const validator = app.get('validator');
    const util = app.get('util');
    const urlLib = app.get('urlLib');
    const emailLib = app.get('email');
    const cosActivities = app.get('cosActivities');
    const Promise = app.get('Promise');
    const cosEtherpad = app.get('cosEtherpad');
    const decode = require('html-entities').decode;
    const https = require('https');
    const crypto = require('crypto');
    const path = require('path');

    const loginCheck = app.get('middleware.loginCheck');
    const isSuperAdmin = app.get('middleware.isSuperAdmin');
    const asyncMiddleware = app.get('middleware.asyncMiddleware');
    const authTokenRestrictedUse = app.get('middleware.authTokenRestrictedUse');
    const speedLimiter = app.get('speedLimiter');
    const rateLimiter = app.get('rateLimiter');
    const cosUpload = app.get('cosUpload');

    const User = models.User;
    const UserConnection = models.UserConnection;
    const Group = models.Group;
    const GroupMemberUser = models.GroupMemberUser;
    const Topic = models.Topic;
    const TopicMemberUser = models.TopicMemberUser;
    const TopicMemberGroup = models.TopicMemberGroup;
    const TopicJoin = models.TopicJoin;
    const TopicReport = models.TopicReport;
    const TopicInviteUser = models.TopicInviteUser;

    const Report = models.Report;

    const Comment = models.Comment;
    const CommentVote = models.CommentVote;
    const CommentReport = models.CommentReport;

    const Vote = models.Vote;
    const VoteOption = models.VoteOption;
    const VoteList = models.VoteList;
    const VoteDelegation = models.VoteDelegation;

    const TopicComment = models.TopicComment;
    const TopicEvent = models.TopicEvent;
    const TopicVote = models.TopicVote;
    const TopicAttachment = models.TopicAttachment;
    const Attachment = models.Attachment;
    const TopicPin = models.TopicPin;
    const UserNotificationSettings = models.UserNotificationSettings;

    const createDataHash = (dataToHash) => {
        const hmac = crypto.createHmac('sha256', config.encryption.salt);

        hmac.update(dataToHash);

        return hmac.digest('hex');
    };

    const _hasPermission = async function (topicId, userId, level, allowPublic, topicStatusesAllowed, allowSelf) {
        const LEVELS = {
            none: 0, // Enables to override inherited permissions.
            read: 1,
            edit: 2,
            admin: 3
        };
        const minRequiredLevel = level;

        // TODO: That casting to "enum_TopicMemberUsers_level". Sequelize does not support naming enums, through inheritance I have 2 enums that are the same but with different name thus different type in PG. Feature request - https://github.com/sequelize/sequelize/issues/2577
        const result = await db
            .query(
                `SELECT
                    t.visibility = 'public' AS "isPublic",
                    t.status,
                    COALESCE(
                        tmup.level,
                        tmgp.level,
                        CASE
                            WHEN t.visibility = 'public' THEN 'read' ELSE NULL
                        END,
                        'none'
                    ) as level,
                    COALESCE(tmup.level, tmgp.level, 'none')::"enum_TopicMemberUsers_level" >= :level AS "hasDirectAccess"
                FROM "Topics" t
                    LEFT JOIN (
                        SELECT
                            tmu."topicId",
                            tmu."userId",
                            tmu.level::text AS level
                        FROM "TopicMemberUsers" tmu
                        WHERE tmu."deletedAt" IS NULL
                    ) AS tmup ON (tmup."topicId" = t.id AND tmup."userId" = :userId)
                    LEFT JOIN (
                        SELECT
                            tmg."topicId",
                            gm."userId",
                            MAX(tmg.level)::text AS level
                        FROM "TopicMemberGroups" tmg
                            JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                        WHERE tmg."deletedAt" IS NULL
                        AND gm."deletedAt" IS NULL
                        GROUP BY "topicId", "userId"
                    ) AS tmgp ON (tmgp."topicId" = t.id AND tmgp."userId" = :userId)
                WHERE t.id = :topicId
                AND t."deletedAt" IS NULL;
                `,
                {
                    replacements: {
                        topicId: topicId,
                        userId: userId,
                        level: level
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true
                }
            );
        if (result && result[0]) {
            const isPublic = result[0].isPublic;
            const status = result[0].status;
            const hasDirectAccess = result[0].hasDirectAccess;
            const level = result[0].level;
            if (hasDirectAccess || (allowPublic && isPublic) || allowSelf) {
                // If Topic status is not in the allowed list, deny access.
                if (topicStatusesAllowed && !(topicStatusesAllowed.indexOf(status) > -1)) {
                    logger.warn('Access denied to topic due to status mismatch! ', 'topicStatusesAllowed:', topicStatusesAllowed, 'status:', status);

                    return false
                }

                if (!allowSelf && (LEVELS[minRequiredLevel] > LEVELS[level])) {
                    logger.warn('Access denied to topic due to member without permissions trying to delete user! ', 'userId:', userId);

                    return false
                }

                const authorizationResult = {
                    topic: {
                        id: topicId,
                        isPublic: isPublic,
                        status: status,
                        permissions: {
                            level: level,
                            hasDirectAccess: hasDirectAccess
                        }
                    }
                };

                return authorizationResult;
            } else {
                return false
            }
        } else {
            return false
        }
    };

    /**
     * Check if User has sufficient privileges to access the Object.
     *
     * @param {string} level One of TopicMemberUser.LEVELS
     * @param {boolean} [allowPublic=false] Allow access to Topic with "public" visibility.
     * @param {string[]} [topicStatusesAllowed=null] Allow access to Topic which is in one of the allowed statuses. IF null, then any status is OK
     * @param {boolean} [allowSelf=false] Allow access when caller does action to is own user
     *
     * @returns {Function} Express middleware function
     */
    const hasPermission = function (level, allowPublic, topicStatusesAllowed, allowSelf) {
        return async function (req, res, next) {
            const userId = req.user.userId;
            const topicId = req.params.topicId;

            allowPublic = allowPublic ? allowPublic : false;

            if (req.user && req.user.moderator) {
                allowPublic = true;
            }

            topicStatusesAllowed = topicStatusesAllowed ? topicStatusesAllowed : null;
            let allowSelfDelete = allowSelf ? allowSelf : null;
            if (allowSelfDelete && req.user.userId !== req.params.memberId) {
                allowSelfDelete = false;
            }

            if (topicStatusesAllowed && !Array.isArray(topicStatusesAllowed)) {
                throw new Error('topicStatusesAllowed must be an array but was ', topicStatusesAllowed);
            }

            try {
                const authorizationResult = await _hasPermission(topicId, userId, level, allowPublic, topicStatusesAllowed, allowSelfDelete)
                // Add "req.locals" to store info collected from authorization for further use in the request. Might save a query or two for some use cases.
                // Naming convention ".locals" is inspired by "res.locals" - http://expressjs.com/api.html#res.locals
                if (authorizationResult) {
                    req.locals = authorizationResult;
                    return next(null, req, res);
                }

                return res.forbidden('Non disponi dei permessi necessari a completare questa operazione.');
            } catch (err) {
                if (err) {
                    return next(err);
                }
            }
        };
    };

    const hasVisibility = function (visibility) {
        return async function (req, res, next) {
            try {
                const count = await Topic.count({
                    where: {
                        id: req.params.topicId,
                        visibility: visibility
                    }
                });

                if (!count) {
                    return res.notFound();
                }

                return next();
            } catch (err) {
                return next(err);
            }
        };
    };

    const _isModerator = async function (topicId, userId) {
        const result = await db
            .query(
                `
                SELECT
                    t."id" as "topicId",
                    m."userId"
                FROM "Topics" t
                JOIN "Moderators" m
                    ON (m."userId" = :userId)
                WHERE t.id = :topicId
                AND t."deletedAt" IS NULL
                AND m."deletedAt" IS NULL
                ;`,
                {
                    replacements: {
                        topicId: topicId,
                        userId: userId
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true
                }
            );

        if (result && result[0]) {
            const isUserModerator = result[0].userId === userId;
            const isTopicModerator = result[0].topicId === topicId;

            if (isUserModerator && isTopicModerator) {
                return { isModerator: true };
            }
        }

        return false;
    };

    /**
     * NOTE! This does not block access in case of not being a Moderator, but only adds moderator flag to user object.
     *
     * @returns {Function} Express middleware function
     */
    const isModerator = function () {
        return async function (req, res, next) {
            const topicId = req.params.topicId;
            let userId;

            if (req.user) {
                userId = req.user.userId;
            }

            if (!topicId || !userId) {
                return next(null, req, res);
            }

            const result = await _isModerator(topicId, userId)
            if (result) {
                req.user.moderator = result.isModerator;
            }

            return next(null, req, res);
        };
    };

    /**
     * Middleware to check for Moderator permissions. Rejects request if there are no Moderator permissions.
     *
     * @returns {Function} Express middleware function
     */
    const hasPermissionModerator = function () {
        return async function (req, res, next) {
            const topicId = req.params.topicId;
            let userId;

            if (req.user) {
                userId = req.user.userId;
            }

            if (!topicId || !userId) {
                return res.unauthorised();
            }
            try {
                const result = await _isModerator(topicId, userId);
                if (result) {
                    req.user.moderator = result.isModerator;

                    return next(null, req, res);
                } else {
                    return res.unauthorised();
                }
            } catch (err) {
                return next(err);
            }
        };
    };

    const isCommentCreator = function () {
        return async function (req, res, next) {
            const userId = req.user.userId;
            const commentId = req.params.commentId;

            try {
                const comment = await Comment.findOne({
                    where: {
                        id: commentId,
                        creatorId: userId,
                        deletedAt: null
                    }
                });

                if (comment) {
                    return next('route');
                } else {
                    return res.forbidden('Non disponi dei permessi necessari a completare questa operazione.');
                }
            } catch (err) {
                return next(err);
            }
        };
    };

    const getVoteResults = async function (voteId, userId) {
        let includeVoted = '';
        if (userId) {
            includeVoted = ',(SELECT true FROM votes WHERE "userId" = :userId AND "optionId" = v."optionId") as "selected" ';
        }

        let sql = `
            WITH
            RECURSIVE delegations("voteId", "toUserId", "byUserId", depth) AS (
                SELECT
                        "voteId",
                        "toUserId",
                        "byUserId",
                            1
                        FROM "VoteDelegations" vd
                        WHERE vd."voteId" = :voteId
                            AND vd."deletedAt" IS NULL

                        UNION ALL

                        SELECT
                            vd."voteId",
                            vd."toUserId",
                            dc."byUserId",
                            dc.depth+1
                        FROM delegations dc, "VoteDelegations" vd
                        WHERE vd."byUserId" = dc."toUserId"
                            AND vd."voteId" = dc."voteId"
                            AND vd."deletedAt" IS NULL
                    ),
                    indirect_delegations("voteId", "toUserId", "byUserId", depth) AS (
                        SELECT DISTINCT ON("byUserId")
                            "voteId",
                            "toUserId",
                            "byUserId",
                            depth
                        FROM delegations
                        ORDER BY "byUserId", depth DESC
                    ),
                    vote_groups("voteId", "userId", "optionGroupId", "updatedAt") AS (
                        SELECT DISTINCT ON (vl."userId") vl."voteId", vl."userId", vli."optionGroupId", vl."updatedAt"
                        FROM (
                            SELECT DISTINCT ON (vl."userHash", MAX(vl."updatedAt"))
                            vl."userId",
                            vl."voteId",
                            MAX(vl."updatedAt") as "updatedAt"
                            FROM "VoteLists" vl
                            WHERE vl."voteId" = :voteId
                            AND vl."deletedAt" IS NULL
                            GROUP BY vl."userHash", vl."userId", vl."voteId"
                            ORDER BY MAX(vl."updatedAt") DESC
                        ) vl
                        JOIN "VoteLists" vli
                        ON
                            vli."userId" = vl."userId"
                            AND vl."voteId" = vli."voteId"
                            AND vli."updatedAt" = vl."updatedAt"
                        WHERE vl."voteId" = :voteId
                    ),
                    votes("voteId", "userId", "optionId", "optionGroupId") AS (
                        SELECT
                            vl."voteId",
                            vl."userId",
                            vl."optionId",
                            vl."optionGroupId"
                        FROM "VoteLists" vl
                        JOIN vote_groups vg ON (vl."voteId" = vg."voteId" AND vl."optionGroupId" = vg."optionGroupId")
                        JOIN "Votes" v ON v.id = vl."voteId"
                        WHERE v."authType"='${Vote.AUTH_TYPES.soft}' AND vl."voteId" = :voteId
                        UNION ALL
                        SELECT
                            vl."voteId",
                            vl."userId",
                            vl."optionId",
                            vl."optionGroupId"
                        FROM "VoteLists" vl
                        JOIN vote_groups vg ON (vl."voteId" = vg."voteId" AND vl."optionGroupId" = vg."optionGroupId")
                        JOIN "Votes" v ON v.id = vl."voteId"
                        WHERE v."authType"='${Vote.AUTH_TYPES.hard}' AND vl."voteId" = :voteId
                        AND vl."userId" IN (
                            SELECT "userId" FROM (
                                SELECT DISTINCT ON (vl."userHash")
                                vl."userId",
                                vl."userHash",
                                MAX(vl."updatedAt")
                                FROM "VoteLists" vl
                                WHERE vl."voteId" = :voteId
                                GROUP BY vl."userId", vl."userHash", vl."updatedAt" ORDER BY vl."userHash", vl."updatedAt" DESC
                            ) vu
                        )
                    ),
                    votes_with_delegations("voteId", "userId", "optionId", "optionGroupId", "byUserId", depth) AS (
                        SELECT
                            v."voteId",
                            v."userId",
                            v."optionId",
                            v."optionGroupId",
                            id."byUserId",
                            id."depth"
                        FROM votes v
                        LEFT JOIN indirect_delegations id ON (v."userId" = id."toUserId")
                        WHERE v."userId" NOT IN (SELECT "byUserId" FROM indirect_delegations WHERE "voteId"=v."voteId")
                    )

                SELECT
                    SUM(v."voteCount") as "voteCount",
                    v."optionId",
                    v."voteId",
                    (SELECT vc.count + vd.count + dt.count
                        FROM (
                            SELECT COUNT (*) FROM (
                                SELECT DISTINCT ON ("userId")
                                     "userId"
                                FROM votes_with_delegations
                                WHERE "byUserId" IS NULL
                            ) nd
                        ) vc
                        JOIN (
                            SELECT COUNT(*) FROM (
                                SELECT "byUserId" FROM votes_with_delegations WHERE "byUserId" IS NOT NULL GROUP BY "byUserId"
                                ) d
                        ) vd ON vd."count" = vd."count"
                        JOIN (
                        SELECT COUNT(*) FROM (
                            SELECT vl."userId" FROM "VoteLists" vl JOIN votes_with_delegations vd ON vd."userId" = vl."userId" WHERE vd."byUserId" IS NOT NULL GROUP BY vl."userId"
                            ) dt
                        ) dt ON dt."count" = dt."count"
                    ) AS "votersCount",
                    vo."value"
                    ${includeVoted}
                FROM (
                    SELECT
                        COUNT(v."optionId") + 1 as "voteCount",
                        v."optionId",
                        v."optionGroupId",
                        v."voteId"
                    FROM votes_with_delegations v
                    WHERE v.depth IS NOT NULL
                    GROUP BY v."optionId", v."optionGroupId", v."voteId"

                    UNION ALL

                    SELECT
                        COUNT(v."optionId") as "voteCount",
                        v."optionId",
                        v."optionGroupId",
                        v."voteId"
                    FROM votes_with_delegations v
                    WHERE v.depth IS NULL
                    GROUP BY v."optionId", v."optionGroupId", v."voteId"
                ) v
                LEFT JOIN "VoteOptions" vo ON (v."optionId" = vo."id")
                GROUP BY v."optionId", v."voteId", vo."value"
        ;`;

        return db
            .query(sql,
                {
                    replacements: {
                        voteId: voteId,
                        userId: userId
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true
                }
            );
    };

    const _topicReadUnauth = async function (topicId, include) {
        await _syncTopicAuthors(topicId); // TODO: On every public topic read we sync authors with EP, can we do better?

        let join = '';
        let returncolumns = '';

        if (include) {
            if (include.indexOf('vote') > -1) {
                join += `
                LEFT JOIN (
                    SELECT "voteId", to_json(array(
                        SELECT CONCAT(id, ':', value)
                        FROM "VoteOptions"
                        WHERE "deletedAt" IS NULL AND vo."voteId"="voteId"
                    )) as "optionIds"
                    FROM "VoteOptions" vo
                    WHERE vo."deletedAt" IS NULL
                    GROUP BY "voteId"
                ) AS vo ON vo."voteId"=tv."voteId" `;

                returncolumns += `
                    , vo."optionIds" as "vote.options"
                    , tv."voteId" as "vote.id"
                    , tv."authType" as "vote.authType"
                    , tv."createdAt" as "vote.createdAt"
                    , tv."delegationIsAllowed" as "vote.delegationIsAllowed"
                    , tv."description" as "vote.description"
                    , tv."endsAt" as "vote.endsAt"
                    , tv."reminderSent" AS "vote.reminderSent"
                    , tv."reminderTime" AS "vote.reminderTime"
                    , tv."maxChoices" as "vote.maxChoices"
                    , tv."minChoices" as "vote.minChoices"
                    , tv."type" as "vote.type"
                    , tv."autoClose" as "vote.autoClose"
                `;
            }
            if (include.indexOf('event') > -1) {
                join += `
                    LEFT JOIN (
                        SELECT COUNT(events.id) as count,
                        events."topicId"
                        FROM "TopicEvents" events
                        WHERE events."topicId" = :topicId
                        AND events."deletedAt" IS NULL
                        GROUP BY events."topicId"
                    ) as te ON te."topicId" = t.id
                    `;
                returncolumns += `
                    , COALESCE(te.count, 0) AS "events.count"
                    `;
            }
        }

        const [topic] = await db
            .query(
                `SELECT
                     t.id,
                     t.title,
                     t.description,
                     t.status,
                     t.visibility,
                     t.categories,
                     t."endsAt",
                     t."padUrl",
                     t."updatedAt",
                     t."createdAt",
                     t."hashtag",
                     c.id as "creator.id",
                     c.name as "creator.name",
                     c.birthday as "creator.birthday",
                     'none' as "permission.level",
                     muc.count as "members.users.count",
                     COALESCE(mgc.count, 0) as "members.groups.count",
                     tv."voteId",
                     tr."id" AS "report.id",
                     tr."moderatedReasonType" AS "report.moderatedReasonType",
                     tr."moderatedReasonText" AS "report.moderatedReasonText",
                     au.authors
                     ${returncolumns}
                FROM "Topics" t
                    LEFT JOIN "Users" c ON (c.id = t."creatorId")
                    LEFT JOIN (
                        SELECT tmu."topicId", COUNT(tmu."memberId") AS "count" FROM (
                            SELECT
                                tmuu."topicId",
                                tmuu."userId" AS "memberId"
                            FROM "TopicMemberUsers" tmuu
                            WHERE tmuu."deletedAt" IS NULL
                            UNION
                            SELECT
                                tmg."topicId",
                                gm."userId" AS "memberId"
                            FROM "TopicMemberGroups" tmg
                                LEFT JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                                JOIN "Groups" gr on gr.id = tmg."groupId"
                            WHERE tmg."deletedAt" IS NULL
                            AND gm."deletedAt" IS NULL
                            AND gr."deletedAt" IS NULL
                        ) AS tmu GROUP BY "topicId"
                    ) AS muc ON (muc."topicId" = t.id)
                    LEFT JOIN (
                        SELECT tmgc."topicId", count(tmgc."groupId") AS "count"
                        FROM "TopicMemberGroups" tmgc
                        JOIN "Groups" gc
                            ON gc.id = tmgc."groupId"
                        WHERE tmgc."deletedAt" IS NULL
                        AND gc."deletedAt" IS NULL
                        GROUP BY tmgc."topicId"
                    ) AS mgc ON (mgc."topicId" = t.id)
                    LEFT JOIN (
                        SELECT
                            t.id as "topicId",
                            json_agg(u) as authors
                        FROM
                        "Topics" t
                        LEFT JOIN (SELECT id,  name FROM "Users") AS u
                        ON
                        u.id IN (SELECT unnest(t."authorIds"))
                        GROUP BY t.id
                    ) AS au ON au."topicId" = t.id
                    LEFT JOIN (
                        SELECT
                            tv."topicId",
                            tv."voteId",
                            v."authType",
                            v."createdAt",
                            v."delegationIsAllowed",
                            v."description",
                            v."endsAt",
                            v."reminderSent",
                            v."reminderTime",
                            v."maxChoices",
                            v."minChoices",
                            v."type",
                            v."autoClose"
                        FROM "TopicVotes" tv INNER JOIN
                            (
                                SELECT
                                    MAX("createdAt") as "createdAt",
                                    "topicId"
                                FROM "TopicVotes"
                                GROUP BY "topicId"
                            ) AS _tv ON (_tv."topicId" = tv."topicId" AND _tv."createdAt" = tv."createdAt")
                        LEFT JOIN "Votes" v
                                ON v.id = tv."voteId"
                    ) AS tv ON (tv."topicId" = t.id)
                    LEFT JOIN "TopicReports" tr ON (tr."topicId" = t.id AND tr."resolvedById" IS NULL AND tr."deletedAt" IS NULL)
                    ${join}
                WHERE t.id = :topicId
                  AND t.visibility = 'public'
                  AND t."deletedAt" IS NULL
                  `,
                {
                    replacements: {
                        topicId: topicId
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true,
                    nest: true
                }
            );

        if (!topic) {
            return;
        }

        topic.url = urlLib.getFe('/topics/:topicId', { topicId: topic.id });

        if (include && include.indexOf('vote') > -1 && topic.vote && topic.vote.id) {
            const voteResults = await getVoteResults(topic.vote.id);
            const options = [];

            topic.vote.options.forEach(function (option) {
                option = option.split(':');
                const o = {
                    id: option[0],
                    value: option[1]
                };
                if (voteResults && voteResults.length) {
                    const res = _.find(voteResults, { 'optionId': o.id });
                    if (res) {
                        o.voteCount = res.voteCount;
                    }
                }
                options.push(o);
            });

            if (voteResults && voteResults.length) {
                topic.vote.votersCount = voteResults[0].votersCount;
            }

            topic.vote.options = {
                count: options.length,
                rows: options
            };

            if (!topic.report.id) {
                delete topic.report;
            }
        } else {
            delete topic.vote;

            if (!topic.report.id) {
                delete topic.report;
            }
        }

        return topic;
    };

    const _topicReadAuth = async function (topicId, include, user) {
        await _syncTopicAuthors(topicId);

        let join = '';
        let returncolumns = '';
        let authorColumns = ' u.id, u.name ';

        if (include && !Array.isArray(include)) {
            include = [include];
        }

        if (include) {
            if (include.indexOf('vote') > -1) {
                join += `
                    LEFT JOIN (
                        SELECT "voteId", to_json(array(
                            SELECT CONCAT(id, ':', value)
                            FROM "VoteOptions"
                            WHERE "deletedAt" IS NULL AND vo."voteId"="voteId"
                        )) as "optionIds"
                        FROM "VoteOptions" vo
                        WHERE vo."deletedAt" IS NULL
                        GROUP BY "voteId"
                    ) AS vo ON vo."voteId"=tv."voteId" `;
                returncolumns += `
                    , vo."optionIds" as "vote.options"
                    , tv."voteId" as "vote.id"
                    , tv."authType" as "vote.authType"
                    , tv."createdAt" as "vote.createdAt"
                    , tv."reminderSent" AS "vote.reminderSent"
                    , tv."reminderTime" AS "vote.reminderTime"
                    , tv."delegationIsAllowed" as "vote.delegationIsAllowed"
                    , tv."description" as "vote.description"
                    , tv."endsAt" as "vote.endsAt"
                    , tv."maxChoices" as "vote.maxChoices"
                    , tv."minChoices" as "vote.minChoices"
                    , tv."type" as "vote.type"
                    , tv."autoClose" as "vote.autoClose"
                    `;
            }

            if (include.indexOf('event') > -1) {
                join += `
                    LEFT JOIN (
                        SELECT COUNT(events.id) as count,
                        events."topicId"
                        FROM "TopicEvents" events
                        WHERE events."topicId" = :topicId
                        AND events."deletedAt" IS NULL
                        GROUP BY events."topicId"
                    ) as te ON te."topicId" = t.id
                `;
                returncolumns += `
                    , COALESCE(te.count, 0) AS "events.count"
                `;
            }
        }

        if (user.moderator) {
            returncolumns += `
            , c.email as "creator.email"
            , uc."connectionData"::jsonb->'phoneNumber' AS "creator.phoneNumber"
            `;

            returncolumns += `
            , tr."type" AS "report.type"
            , tr."text" AS "report.text"
            `;
            authorColumns += `
            , u.email
            `;
        }

        const result = await db.query(
            `SELECT
                    t.id,
                    t.title,
                    t.description,
                    t.status,
                    t.visibility,
                    t.hashtag,
                    CASE
                    WHEN COALESCE(tmup.level, tmgp.level, 'none') = 'admin' THEN tj.token
                    ELSE NULL
                    END as "join.token",
                    CASE
                    WHEN COALESCE(tmup.level, tmgp.level, 'none') = 'admin' THEN tj.level
                    ELSE NULL
                    END as "join.level",
                    CASE
                    WHEN tp."topicId" = t.id THEN true
                    ELSE false
                    END as "pinned",
                    t.categories,
                    t."endsAt",
                    t."padUrl",
                    t."createdAt",
                    t."updatedAt",
                    c.id as "creator.id",
                    c.name as "creator.name",
                    c.birthday as "creator.birthday",
                    COALESCE(
                        tmup.level,
                        tmgp.level,
                            'none '
                    ) as "permission.level",
                    muc.count as "members.users.count",
                    COALESCE(mgc.count, 0) as "members.groups.count",
                    tv."voteId",
                    u.id as "user.id",
                    u.name as "user.name",
                    u.language as "user.language",
                    tr.id AS "report.id",
                    tr."moderatedReasonType" AS "report.moderatedReasonType",
                    tr."moderatedReasonText" AS "report.moderatedReasonText",
                    au.authors
                    ${returncolumns}
            FROM "Topics" t
                    LEFT JOIN (
                    SELECT
                        tmu."topicId",
                        tmu."userId",
                        tmu.level::text AS level
                    FROM "TopicMemberUsers" tmu
                    WHERE tmu."deletedAt" IS NULL
                ) AS tmup ON (tmup."topicId" = t.id AND tmup."userId" = :userId)
                LEFT JOIN (
                    SELECT
                        tmg."topicId",
                        gm."userId",
                        MAX(tmg.level)::text AS level
                    FROM "TopicMemberGroups" tmg
                        LEFT JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                    WHERE tmg."deletedAt" IS NULL
                    AND gm."deletedAt" IS NULL
                    GROUP BY "topicId", "userId"
                ) AS tmgp ON (tmgp."topicId" = t.id AND tmgp."userId" = :userId)
                LEFT JOIN "Users" c ON (c.id = t."creatorId")
                LEFT JOIN "UserConnections" uc ON (uc."userId" = t."creatorId")
                LEFT JOIN (
                    SELECT
                        t.id AS "topicId",
                        json_agg(u) as authors
                    FROM
                    "Topics" t
                    LEFT JOIN (SELECT ${authorColumns} FROM "Users" u ) u
                    ON
                    u.id IN (SELECT unnest(t."authorIds"))
                    GROUP BY t.id
                ) AS au ON au."topicId" = t.id
                LEFT JOIN (
                    SELECT tmu."topicId", COUNT(tmu."memberId") AS "count" FROM (
                        SELECT
                            tmuu."topicId",
                            tmuu."userId" AS "memberId"
                        FROM "TopicMemberUsers" tmuu
                        WHERE tmuu."deletedAt" IS NULL
                        UNION
                        SELECT
                            tmg."topicId",
                            gm."userId" AS "memberId"
                        FROM "TopicMemberGroups" tmg
                            LEFT JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                            JOIN "Groups" gr ON gr.id = tmg."groupId"
                        WHERE tmg."deletedAt" IS NULL
                        AND gm."deletedAt" IS NULL
                        AND gr."deletedAt" IS NULL
                    ) AS tmu GROUP BY "topicId"
                ) AS muc ON (muc."topicId" = t.id)
                LEFT JOIN (
                    SELECT "topicId", count("groupId") AS "count"
                    FROM "TopicMemberGroups" tmg
                    JOIN "Groups" g ON tmg."groupId" = g.id
                    WHERE tmg."deletedAt" IS NULL
                    AND g."deletedAt" IS NULL
                    GROUP BY "topicId"
                ) AS mgc ON (mgc."topicId" = t.id)
                LEFT JOIN "Users" u ON (u.id = :userId)
                LEFT JOIN (
                    SELECT
                        tv."topicId",
                        tv."voteId",
                        v."authType",
                        v."createdAt",
                        v."delegationIsAllowed",
                        v."description",
                        v."endsAt",
                        v."maxChoices",
                        v."minChoices",
                        v."reminderSent",
                        v."reminderTime",
                        v."type",
                        v."autoClose"
                    FROM "TopicVotes" tv INNER JOIN
                        (
                            SELECT
                                MAX("createdAt") as "createdAt",
                                "topicId"
                            FROM "TopicVotes"
                            GROUP BY "topicId"
                        ) AS _tv ON (_tv."topicId" = tv."topicId" AND _tv."createdAt" = tv."createdAt")
                    LEFT JOIN "Votes" v
                            ON v.id = tv."voteId"
                ) AS tv ON (tv."topicId" = t.id)
                LEFT JOIN "TopicPins" tp ON tp."topicId" = t.id AND tp."userId" = :userId
                LEFT JOIN "TopicReports" tr ON (tr."topicId" = t.id AND tr."resolvedById" IS NULL AND tr."deletedAt" IS NULL)
                LEFT JOIN "TopicJoins" tj ON (tj."topicId" = t.id AND tj."deletedAt" IS NULL)
                ${join}
            WHERE t.id = :topicId
                AND t."deletedAt" IS NULL
            `,
            {
                replacements: {
                    topicId: topicId,
                    userId: user.id
                },
                type: db.QueryTypes.SELECT,
                raw: true,
                nest: true
            }
        );
        let topic;
        if (result && result.length && result[0]) {
            topic = result[0];
        } else {
            logger.warn('Topic not found', topicId);
            return;
        }
        topic.padUrl = cosEtherpad.getUserAccessUrl(topic, topic.user.id, topic.user.name, 'it');
        topic.url = urlLib.getFe('/topics/:topicId', { topicId: topic.id });

        if (topic.visibility === Topic.VISIBILITY.public && topic.permission.level === TopicMemberUser.LEVELS.none) {
            topic.permission.level = TopicMemberUser.LEVELS.read;
        }
        // Remove the user info from output, was only needed for padUrl generation
        delete topic.user;

        if (include && include.indexOf('vote') > -1 && topic.vote && topic.vote.id) {

            const voteResult = await getVoteResults(topic.vote.id, user.id);
            const options = [];
            let hasVoted = false;

            topic.vote.options.forEach(function (option) {
                option = option.split(':');
                const o = {
                    id: option[0],
                    value: option[1]
                };
                if (voteResult) {
                    const res = _.find(voteResult, { 'optionId': o.id });
                    if (res) {
                        const count = parseInt(res.voteCount, 10);
                        if (count) {
                            o.voteCount = count;
                        }
                        if (res.selected) {
                            o.selected = res.selected;
                            hasVoted = true;
                        }
                    }
                }
                options.push(o);
            });

            if (voteResult && voteResult.length) {
                topic.vote.votersCount = voteResult[0].votersCount;
            }

            if (topic.vote.authType === Vote.AUTH_TYPES.hard && hasVoted) {
                topic.vote.downloads = { };
            }

            topic.vote.options = {
                count: options.length,
                rows: options
            };
        } else {
            delete topic.vote;
        }

        if (!topic.report.id) {
            delete topic.report;
        }

        return topic;
    };

    const getAllVotesResults = async (userId) => {
        let where = '';
        let join = '';
        let select = '';
        if (!userId) {
            where = ` AND t.visibility = '${Topic.VISIBILITY.public}'`;
        } else {
            select = injectReplacements(', (SELECT true FROM pg_temp.votes(v."voteId") WHERE "userId" = :userId AND "optionId" = v."optionId") as "selected" ', Sequelize.postgres, { userId });
            where = `AND COALESCE(tmup.level, tmgp.level, 'none')::"enum_TopicMemberUsers_level" > 'none'`;
            join += injectReplacements(`LEFT JOIN (
                        SELECT
                            tmu."topicId",
                            tmu."userId",
                            tmu.level::text AS level
                        FROM "TopicMemberUsers" tmu
                        WHERE tmu."deletedAt" IS NULL
                    ) AS tmup ON (tmup."topicId" = t.id AND tmup."userId" = :userId)
                    LEFT JOIN (
                        SELECT
                            tmg."topicId",
                            gm."userId",
                            MAX(tmg.level)::text AS level
                        FROM "TopicMemberGroups" tmg
                            LEFT JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                        WHERE tmg."deletedAt" IS NULL
                        AND gm."deletedAt" IS NULL
                        GROUP BY "topicId", "userId"
                    ) AS tmgp ON (tmgp."topicId" = t.id AND tmgp."userId" = :userId)
            `, Sequelize.postgres, { userId });
        }
        const query = `
                        CREATE OR REPLACE FUNCTION pg_temp.delegations(uuid)
                            RETURNS TABLE("voteId" uuid, "toUserId" uuid, "byUserId" uuid, depth INT)
                                AS $$
                                    WITH  RECURSIVE q ("voteId", "toUserId", "byUserId", depth)
                                        AS
                                            (
                                            SELECT
                                                vd."voteId",
                                                vd."toUserId",
                                                vd."byUserId",
                                                1
                                            FROM "VoteDelegations" vd
                                            WHERE vd."voteId" = $1
                                              AND vd."deletedAt" IS NULL
                                            UNION ALL
                                            SELECT
                                                vd."voteId",
                                                vd."toUserId",
                                                dc."byUserId",
                                                dc.depth+1
                                            FROM q dc, "VoteDelegations" vd
                                            WHERE vd."byUserId" = dc."toUserId"
                                              AND vd."voteId" = dc."voteId"
                                              AND vd."deletedAt" IS NULL
                                            )
                            SELECT * FROM q; $$
                        LANGUAGE SQL;
                        CREATE OR REPLACE FUNCTION pg_temp.indirect_delegations(uuid)
                            RETURNS TABLE("voteId" uuid, "toUserId" uuid, "byUserId" uuid, depth int)
                                AS $$
                                    SELECT DISTINCT ON("byUserId")
                                        "voteId",
                                        "toUserId",
                                        "byUserId",
                                        depth
                                    FROM pg_temp.delegations($1)
                                    ORDER BY "byUserId", depth DESC; $$
                            LANGUAGE SQL;
                        CREATE OR REPLACE FUNCTION pg_temp.vote_groups(uuid)
                            RETURNS TABLE ("voteId" uuid, "userId" uuid, "optionGroupId" character varying , "updatedAt" timestamp with time zone)
                            AS $$
                            SELECT DISTINCT ON (vl."userId") vl."voteId", vl."userId", vli."optionGroupId", vl."updatedAt"
                            FROM (
                                SELECT DISTINCT ON (vl."userHash", MAX(vl."updatedAt"))
                                    vl."userId",
                                    vl."voteId",
                                    MAX(vl."updatedAt") as "updatedAt"
                                FROM "VoteLists" vl
                                WHERE vl."voteId" = $1
                                    AND vl."deletedAt" IS NULL
                                GROUP BY vl."userHash", vl."userId", vl."voteId"
                                ORDER BY MAX(vl."updatedAt") DESC
                            ) vl
                            JOIN "VoteLists" vli
                            ON
                                vli."userId" = vl."userId"
                                AND vl."voteId" = vli."voteId"
                                AND vli."updatedAt" = vl."updatedAt"
                              ; $$
                            LANGUAGE SQL;
                        CREATE OR REPLACE FUNCTION pg_temp.votes(uuid)
                            RETURNS TABLE ("voteId" uuid, "userId" uuid, "optionId" uuid, "optionGroupId" character varying)
                            AS $$
                                SELECT
                                    vl."voteId",
                                    vl."userId",
                                    vl."optionId",
                                    vl."optionGroupId"
                                FROM "VoteLists" vl
                                JOIN pg_temp.vote_groups($1) vg ON (vl."voteId" = vg."voteId" AND vl."optionGroupId" = vg."optionGroupId")
                                JOIN "Votes" vo ON vo.id = vl."voteId"
                                WHERE vo."authType"='${Vote.AUTH_TYPES.soft}' AND vl."voteId" = $1
                                UNION ALL
                                SELECT
                                    vl."voteId",
                                    vl."userId",
                                    vl."optionId",
                                    vl."optionGroupId"
                                FROM "VoteLists" vl
                                JOIN pg_temp.vote_groups($1) vg ON (vl."voteId" = vg."voteId" AND vl."optionGroupId" = vg."optionGroupId")
                                JOIN "Votes" vo ON vo.id = vl."voteId"
                                WHERE vo."authType"='${Vote.AUTH_TYPES.hard}' AND vl."voteId" = $1
                                AND vl."userId" IN (
                                    SELECT "userId" FROM (
                                        SELECT DISTINCT ON (vl."userHash")
                                        vl."userId",
                                        vl."userHash",
                                        MAX(vl."updatedAt")
                                        FROM "VoteLists" vl
                                        WHERE vl."voteId" = $1
                                        GROUP BY vl."userId", vl."userHash", vl."updatedAt" ORDER BY vl."userHash", vl."updatedAt" DESC
                                    ) vu
                                )
                                $$
                            LANGUAGE SQL;
                        CREATE OR REPLACE FUNCTION pg_temp.votes_with_delegations(uuid)
                            RETURNS TABLE ("voteId" uuid, "userId" uuid, "optionId" uuid, "optionGroupId" varchar(8), depth int)
                            AS $$
                                SELECT
                                    v."voteId",
                                    v."userId",
                                    v."optionId",
                                    v."optionGroupId",
                                    id."depth"
                                FROM pg_temp.votes($1) v
                                LEFT JOIN pg_temp.indirect_delegations($1) id ON (v."userId" = id."toUserId")
                                WHERE v."userId" NOT IN (SELECT "byUserId" FROM pg_temp.indirect_delegations($1) WHERE "voteId"=v."voteId");
                                $$
                            LANGUAGE SQL;
                        CREATE OR REPLACE FUNCTION pg_temp.get_vote_results (uuid)
                            RETURNS TABLE ("voteCount" bigint, "optionId" uuid, "optionGroupId" varchar(8), "voteId" uuid)
                            AS $$
                                SELECT
                                    COUNT(v."optionId") + 1 as "voteCount",
                                    v."optionId",
                                    v."optionGroupId",
                                    v."voteId"
                                FROM pg_temp.votes_with_delegations($1) v
                                WHERE v.depth IS NOT NULL
                                GROUP BY v."optionId", v."optionGroupId", v."voteId"

                                UNION ALL

                                SELECT
                                    COUNT(v."optionId") as "voteCount",
                                    v."optionId",
                                    v."optionGroupId",
                                    v."voteId"
                                FROM pg_temp.votes_with_delegations($1) v
                                WHERE v.depth IS NULL
                                GROUP BY v."optionId", v."optionGroupId", v."voteId"; $$
                            LANGUAGE SQL;
                        CREATE OR REPLACE FUNCTION pg_temp.get_voters_count (uuid)
                            RETURNS TABLE ("votersCount" bigint)
                            AS $$
                                SELECT COUNT(*) as "votersCount" FROM
                                (
                                    SELECT "userId" FROM (
                                        SELECT DISTINCT ON (vl."userHash")
                                        vl."userId",
                                        vl."userHash",
                                        MAX(vl."updatedAt")
                                        FROM "VoteLists" vl
                                        WHERE vl."voteId" = $1
                                        GROUP BY vl."userId", vl."userHash", vl."updatedAt" ORDER BY vl."userHash", vl."updatedAt" DESC
                                    ) vu
                                ) c
                             $$
                            LANGUAGE SQL;

                        SELECT
                            SUM(v."voteCount") as "voteCount",
                            vc."votersCount",
                            v."optionId",
                            v."voteId",
                            vo."value"
                            ${select}
                        FROM "Topics" t
                        LEFT JOIN "TopicVotes" tv
                            ON tv."topicId" = t.id AND tv."deletedAt" IS NULL
                        LEFT JOIN pg_temp.get_vote_results(tv."voteId") v ON v."voteId" = tv."voteId"
                        LEFT JOIN "VoteOptions" vo ON v."optionId" = vo.id
                        LEFT JOIN pg_temp.get_voters_count(tv."voteId") vc ON vc."votersCount" = vc."votersCount"
                        ${join}
                        WHERE  t."deletedAt" IS NULL
                        AND v."optionId" IS NOT NULL
                        AND v."voteId" IS NOT NULL
                        AND vo."value" IS NOT NULL
                        ${where}
                        GROUP BY v."optionId", v."voteId", vo."value", vc."votersCount"
                    ;`;

        return db
            .query(
                query,
                {
                    type: db.QueryTypes.SELECT,
                    raw: true
                }
            );
    };

    const _syncTopicAuthors = async function (topicId) {
        const authorIds = await cosEtherpad.getTopicPadAuthors(topicId);
        if (authorIds && authorIds.length) {
            await Topic.update({
                authorIds
            }, {
                where: {
                    id: topicId
                }
            });
        }
    };

    /**
     * Create a new Topic
     */
    app.post('/api/users/:userId/topics', loginCheck(), async function (req, res, next) {
        try {
            // I wish Sequelize Model.build supported "fields". This solution requires you to add a field here once new are defined in model.
            let topic = Topic.build({
                visibility: Topic.VISIBILITY.private,
                creatorId: req.user.userId,
                categories: req.body.categories,
                endsAt: req.body.endsAt,
                authorIds: [req.user.userId]
            });

            topic.padUrl = cosEtherpad.getTopicPadUrl(topic.id);

            const topicDescription = req.body.description;

            const user = await User.findOne({
                where: {
                    id: req.user.userId
                },
                attributes: ['id', 'name', 'language']
            });

            // Create topic on Etherpad side
            await cosEtherpad.createTopic(topic.id, 'it', topicDescription);

            let topicJoin;

            await db.transaction(async function (t) {
                await topic.save({ transaction: t });
                const topicJoinPromise = TopicJoin.create(
                    {
                        topicId: topic.id
                    },
                    {
                        transaction: t
                    }
                );

                const memberUserPromise = topic.addMemberUser(// Magic method by Sequelize - https://github.com/sequelize/sequelize/wiki/API-Reference-Associations#hasmanytarget-options
                    user.id,
                    {
                        through: {
                            level: TopicMemberUser.LEVELS.admin
                        },
                        transaction: t
                    }
                );

                const activityPromise = cosActivities.createActivity(
                    topic,
                    null,
                    {
                        type: 'User',
                        id: req.user.userId,
                        ip: req.ip
                    }
                    , req.method + ' ' + req.path,
                    t
                );
                [topicJoin] = await Promise.all([topicJoinPromise, memberUserPromise, activityPromise]);
                t.afterCommit(async () => {
                    topic = await cosEtherpad.syncTopicWithPad( // eslint-disable-line require-atomic-updates
                        topic.id,
                        req.method + ' ' + req.path,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        }
                    );
                    const authors = await User.findAll({
                        where: {
                            id: topic.authorIds
                        },
                        attributes: ['id', 'name'],
                        raw: true
                    });

                    const resObject = topic.toJSON();
                    resObject.authors = authors;
                    resObject.padUrl = cosEtherpad.getUserAccessUrl(topic, user.id, user.name, 'it');
                    resObject.url = urlLib.getFe('/topics/:topicId', { topicId: topic.id });

                    resObject.pinned = false;
                    resObject.permission = {
                        level: TopicMemberUser.LEVELS.admin
                    };

                    resObject.join = topicJoin.toJSON();

                    return res.created(resObject);
                });
            });
        } catch (err) {
            return next(err);
        }
    });

    //Copy topic
    app.get('/api/users/:userId/topics/:topicId/duplicate', loginCheck(), async function (req, res, next) {
        try {
            // I wish Sequelize Model.build supported "fields". This solution requires you to add a field here once new are defined in model.
            const sourceTopic = await Topic.findOne({
                where: {
                    id: req.params.topicId
                }
            });

            if (sourceTopic.creatorId !== req.user.userId) {
                return res.forbidden();
            }

            let topic = Topic.build({
                visibility: Topic.VISIBILITY.private,
                creatorId: req.user.userId,
                authorIds: [req.user.userId]
            });

            topic.padUrl = cosEtherpad.getTopicPadUrl(topic.id);

            const user = await User.findOne({
                where: {
                    id: req.user.userId
                },
                attributes: ['id', 'name', 'language']
            });

            await db.transaction(async function (t) {
                await cosEtherpad.createPadCopy(req.params.topicId, topic.id);
                await topic.save({ transaction: t });
                await topic.addMemberUser(// Magic method by Sequelize - https://github.com/sequelize/sequelize/wiki/API-Reference-Associations#hasmanytarget-options
                    user.id,
                    {
                        through: {
                            level: TopicMemberUser.LEVELS.admin
                        },
                        transaction: t
                    }
                );

                const attachments = await getTopicAttachments(req.params.topicId);
                const topicJoin = await TopicJoin.create(
                    {
                        topicId: topic.id
                    },
                    {
                        transaction: t
                    }
                );
                attachments.forEach(async (attachment) => {
                    const attachmentClone = await Attachment.create(
                        {
                            name: attachment.name,
                            size: attachment.size,
                            source: attachment.source,
                            type: attachment.type,
                            link: attachment.link,
                            creatorId: attachment.creator.id
                        },
                        {
                            transaction: t
                        }
                    );

                    await TopicAttachment.create(
                        {
                            topicId: topic.id,
                            attachmentId: attachmentClone.id
                        },
                        {
                            transaction: t
                        }
                    );
                });

                await cosActivities.createActivity(
                    topic,
                    null,
                    {
                        type: 'User',
                        id: req.user.userId,
                        ip: req.ip
                    }
                    , req.method + ' ' + req.path,
                    t
                );

                t.afterCommit(async () => {
                    topic = await cosEtherpad.syncTopicWithPad( // eslint-disable-line require-atomic-updates
                        topic.id,
                        req.method + ' ' + req.path,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        }
                    );
                    const authorIds = topic.authorIds;
                    const authors = await User.findAll({
                        where: {
                            id: authorIds
                        },
                        attributes: ['id', 'name'],
                        raw: true
                    });

                    const resObject = topic.toJSON();
                    resObject.authors = authors;
                    resObject.padUrl = cosEtherpad.getUserAccessUrl(topic, user.id, user.name, 'it');
                    resObject.url = urlLib.getFe('/topics/:topicId', { topicId: topic.id });

                    resObject.pinned = false;
                    resObject.permission = {
                        level: TopicMemberUser.LEVELS.admin
                    };
                    resObject.join = topicJoin;
                    return res.created(resObject);
                });
            });
        } catch (err) {
            return next(err);
        }

    });
    /**
     * Read a Topic
     */
    app.get('/api/users/:userId/topics/:topicId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true), isModerator(), async function (req, res, next) {
        try {
            const include = req.query.include;
            const topicId = req.params.topicId;
            const user = req.user;
            const topic = await _topicReadAuth(topicId, include, user);

            if (!topic) {
                return res.notFound();
            }

            return res.ok(topic);
        } catch (err) {
            return next(err);
        }
    });

    app.get('/api/topics/:topicId', async function (req, res, next) {
        let include = req.query.include;
        const topicId = req.params.topicId;

        if (include && !Array.isArray(include)) {
            include = [include];
        }

        try {
            const topic = await _topicReadUnauth(topicId, include);

            if (!topic) {
                return res.notFound();
            }

            return res.ok(topic);
        } catch (err) {
            return next(err);
        }
    });

    app.get('/api/users/:userId/topics/:topicId/inlinecomments', loginCheck(), async (req, res, next) => {
        const topicId = req.params.topicId;
        const user = req.user;

        try {
            const commentRequest = await cosEtherpad.getTopicInlineComments(topicId, user.id, user.name);
            const replyRequest = await cosEtherpad.getTopicInlineCommentReplies(topicId, user.id, user.name);
            const replies = Object.values(replyRequest.replies);
            const result = commentRequest.comments;
            replies.forEach(function (reply) {
                if (!result[reply.commentId]) return;
                if (!result[reply.commentId].replies) {
                    result[reply.commentId].replies = [];
                }
                result[reply.commentId].replies.push(reply);
            });

            return res.ok(result);
        } catch (err) {
            return next(err);
        }
    });

    const _topicUpdate = async function (req, res, next) {
        try {
            const topicId = req.params.topicId;
            const statusNew = req.body.status;
            const visibility = req.body.visibility || false;

            let isBackToVoting = false;

            const topic = await Topic
                .findOne({
                    where: { id: topicId },
                    include: [Vote]
                });

            if (!topic) {
                return res.badRequest();
            }

            if (visibility) {
                if (topic.visibility === 'public' && visibility !== 'public') {
                    return res.badRequest('Un topic pubblico non può più tornare ad essere invisibile.');
                }
                else if (topic.visibility === 'private' && visibility !== 'private' && visibility !== 'public') {
                    return res.badRequest('Il campo "visibilità" è malformato.');
                }
                else if (topic.visibility === 'private' && visibility === 'public') {
                    const userGroup = await GroupMemberUser.findOne({where: {userId: req.user.id}});
                    if (!userGroup) {
                        return res.internalServerError("Errore di sistema, il topic non può essere pubblicato.");
                    }
                    const userTopic = await TopicMemberGroup
                            .findOrCreate({
                                where: {
                                    topicId: topicId,
                                    groupId: userGroup.groupId
                                },
                                defaults: {
                                    level: TopicMemberUser.LEVELS.read
                                }
                            });
                    if (!userTopic) {
                        return res.internalServerError("Errore di sistema, il topic non può essere pubblicato.");
                    }
                }
            }

            const statuses = _.values(Topic.STATUSES);
            const vote = topic.Votes[0];

            if (statusNew && statusNew !== topic.status) {
                // The only flow that allows going back in status flow is reopening for voting
                if (statusNew === Topic.STATUSES.voting && topic.status === Topic.STATUSES.followUp) {
                    if (!vote) {
                        return res.badRequest('Invalid status flow. Cannot change Topic status from ' + topic.status + ' to ' + statusNew + ' when the Topic has no Vote created');
                    }
                    isBackToVoting = true;
                } else if (statuses.indexOf(topic.status) > statuses.indexOf(statusNew) || [Topic.STATUSES.voting].indexOf(statusNew) > -1) { // You are not allowed to go "back" in the status flow nor you are allowed to set "voting" directly, it can only be done creating a Vote.
                    return res.badRequest('Invalid status flow. Cannot change Topic status from ' + topic.status + ' to ' + statusNew);
                }
            }

            // NOTE: Description is handled separately below
            const fieldsAllowedToUpdate = ['categories', 'endsAt'];
            if (req.locals.topic.permissions.level === TopicMemberUser.LEVELS.admin) {
                fieldsAllowedToUpdate.push('visibility');
                fieldsAllowedToUpdate.push('status');
            }

            Object.keys(req.body).forEach(function (key) {
                if (fieldsAllowedToUpdate.indexOf(key) >= 0) {
                    topic.set(key, req.body[key]);
                }
            });
            const promisesList = [];
            await db
                .transaction(async function (t) {
                    if (req.body.description) {
                        if (topic.status === Topic.STATUSES.inProgress) {
                            promisesList.push(cosEtherpad
                                .updateTopic(
                                    topicId,
                                    req.body.description
                                ));
                        } else {
                            return res.badRequest(`Cannot update Topic content when status ${topic.status}`);
                        }
                    }

                    promisesList.push(cosActivities
                        .updateActivity(
                            topic,
                            null,
                            {
                                type: 'User',
                                id: req.user.userId,
                                ip: req.ip
                            },
                            req.method + ' ' + req.path,
                            t
                        ));

                    promisesList.push(topic.save({ transaction: t }));

                    if (isBackToVoting) {
                        promisesList.push(TopicEvent
                            .destroy({
                                where: {
                                    topicId: topicId
                                },
                                force: true,
                                transaction: t
                            }));
                    }
                    await Promise.all(promisesList);
                });

            if (req.body.description && topic.status === Topic.STATUSES.inProgress) {
                await cosEtherpad
                    .syncTopicWithPad(
                        topicId,
                        req.method + ' ' + req.path,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        null,
                        true
                    );
            }
        } catch (err) {
            return next(err);
        }
    };

    /**
     * Update Topic info
     */
    app.put('/api/users/:userId/topics/:topicId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.edit, null, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]), async function (req, res, next) {
        try {
            await _topicUpdate(req, res, next);

            return res.ok();
        } catch (err) {
            next(err);
        }
    });

    app.patch('/api/users/:userId/topics/:topicId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.edit, null, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]), async function (req, res, next) {
        try {
            await _topicUpdate(req, res, next);

            return res.noContent();
        } catch (err) {
            next(err);
        }
    });

    /**
     * Update (regenerate) Topic join token (TopicJoin) with a level
     *
     * PUT as there is one TopicJoin for each Topic. Always overwrites previous.
     *
     * @see https://github.com/citizenos/citizenos-fe/issues/311
     */
    app.put('/api/users/:userId/topics/:topicId/join', loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin, null, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]), asyncMiddleware(async function (req, res) {
        const topicId = req.params.topicId;
        const level = req.body.level;
        if (!Object.values(TopicJoin.LEVELS).includes(level)) {
            return res.badRequest('Invalid value for property "level". Possible values are ' + Object.values(TopicJoin.LEVELS) + '.', 1);
        }
        const topicJoin = await TopicJoin.findOne({
            where: {
                topicId: topicId
            }
        });

        topicJoin.token = TopicJoin.generateToken();
        topicJoin.level = level;

        await db
            .transaction(async (t) => {
                await cosActivities
                    .updateActivity(
                        topicJoin,
                        null,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );

                await topicJoin.save({ transaction: t });
                t.afterCommit(() => {
                    return res.ok(topicJoin);
                });
            });
    }));

    /**
     * Update level of an existing token WITHOUT regenerating the token
     *
     * @see https://github.com/citizenos/citizenos-fe/issues/311
     */
    app.put('/api/users/:userId/topics/:topicId/join/:token', loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin, null, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]), asyncMiddleware(async function (req, res) {
        const topicId = req.params.topicId;
        const token = req.params.token;
        const level = req.body.level;

        if (!Object.values(TopicJoin.LEVELS).includes(level)) {
            return res.badRequest('Invalid value for property "level". Possible values are ' + Object.values(TopicJoin.LEVELS) + '.', 1);
        }

        const topicJoin = await TopicJoin.findOne({
            where: {
                topicId: topicId,
                token: token
            }
        });

        if (!topicJoin) {
            return res.notFound('Nothing found for topicId and token combination.');
        }

        topicJoin.level = level;

        await db
            .transaction(async function (t) {
                await cosActivities
                    .updateActivity(
                        topicJoin,
                        null,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );

                await topicJoin.save({ transaction: t });
                t.afterCommit(() => {
                    return res.ok(topicJoin);
                });
            });
    }));


    /**
     * Delete Topic
     */
    app.delete('/api/users/:userId/topics/:topicId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin), async function (req, res, next) {
        try {
            const topic = await Topic.findByPk(req.params.topicId);
            if (!topic) {
                return res.notFound('No such topic found.');
            }

            await db.transaction(async function (t) {
                try {
                    await cosEtherpad.deleteTopic(topic.id);
                } catch (err) {
                    if (!err.message || err.message !== 'padID does not exist') {
                        throw err;
                    }
                }

                // Delete TopicMembers beforehand. Sequelize does not cascade and set "deletedAt" for related objects if "paranoid: true".
                await TopicMemberUser.destroy({
                    where: {
                        topicId: topic.id
                    },
                    force: true,
                    transaction: t
                });

                await TopicMemberGroup.destroy({
                    where: {
                        topicId: topic.id
                    },
                    force: true,
                    transaction: t
                });

                await topic.destroy({
                    transaction: t
                });

                await cosActivities.deleteActivity(topic, null, {
                    type: 'User',
                    id: req.user.userId,
                    ip: req.ip
                }, req.method + ' ' + req.path, t);

                t.afterCommit(() => {
                    return res.ok();
                });
            });
        } catch (err) {
            return next(err);
        }
    });


    /**
     * Get all Topics User belongs to
     */
    app.get('/api/users/:userId/topics', loginCheck(), async function (req, res, next) {
        const userId = req.user.userId;
        let include = req.query.include;
        const visibility = req.query.visibility;
        const creatorId = req.query.creatorId;
        let statuses = req.query.statuses;
        const pinned = req.query.pinned;
        const hasVoted = req.query.hasVoted; // Filter out Topics where User has participated in the voting process.
        const showModerated = req.query.showModerated || false;

        if (statuses && !Array.isArray(statuses)) {
            statuses = [statuses];
        }

        let voteResults = false;
        let join = '';
        let returncolumns = '';

        if (!Array.isArray(include)) {
            include = [include];
        }

        if (include.indexOf('vote') > -1) {
            returncolumns += `
            , (
                SELECT to_json(
                    array (
                        SELECT concat(id, ':', value)
                        FROM   "VoteOptions"
                        WHERE  "deletedAt" IS NULL
                        AND    "voteId" = tv."voteId"
                    )
                )
            ) as "vote.options"
            , tv."voteId" as "vote.id"
            , tv."authType" as "vote.authType"
            , tv."createdAt" as "vote.createdAt"
            , tv."delegationIsAllowed" as "vote.delegationIsAllowed"
            , tv."description" as "vote.description"
            , tv."endsAt" as "vote.endsAt"
            , tv."reminderSent" as "vote.reminderSent"
            , tv."reminderTime" as "vote.reminderTime"
            , tv."maxChoices" as "vote.maxChoices"
            , tv."minChoices" as "vote.minChoices"
            , tv."type" as "vote.type"
            , tv."autoClose" as "vote.autoClose"
            `;
            voteResults = getAllVotesResults(userId);
        }

        if (include.indexOf('event') > -1) {
            join += ` LEFT JOIN (
                        SELECT
                            COUNT(events.id) as count,
                            events."topicId"
                        FROM "TopicEvents" events
                        WHERE events."deletedAt" IS NULL
                        GROUP BY events."topicId"
                    ) AS te ON te."topicId" = t.id
            `;
            returncolumns += `
            , COALESCE(te.count, 0) AS "events.count"
            `;
        }

        let where = ` t."deletedAt" IS NULL
                    AND t.title IS NOT NULL
                    AND COALESCE(tmup.level, tmgp.level, 'none')::"enum_TopicMemberUsers_level" > 'none' `;

        if (visibility) {
            where += ` AND t.visibility=:visibility `;
        }

        if (statuses && statuses.length) {
            where += ` AND t.status IN (:statuses) `;
        }

        if (pinned) {
            where += ` AND tp."topicId" = t.id AND tp."userId" = :userId`;
        }

        if (['true', '1'].includes(hasVoted)) {
            where += ` AND EXISTS (SELECT TRUE FROM "VoteLists" vl WHERE vl."voteId" = tv."voteId" AND vl."userId" = :userId LIMIT 1)`;
        } else if (['false', '0'].includes(hasVoted)) {
            where += ` AND tv."voteId" IS NOT NULL AND t.status = 'voting'::"enum_Topics_status" AND NOT EXISTS (SELECT TRUE FROM "VoteLists" vl WHERE vl."voteId" = tv."voteId" AND vl."userId" = :userId LIMIT 1)`;
        } else {
            logger.warn(`Ignored parameter "voted" as invalid value "${hasVoted}" was provided`);
        }

        if (!showModerated || showModerated == "false") {
            where += ` AND (tr."moderatedAt" IS NULL OR tr."resolvedAt" IS NOT NULL) `;
        } else {
            where += ` AND (tr."moderatedAt" IS NOT NULL AND tr."resolvedAt" IS NULL) `;
        }

        if (creatorId) {
            if (creatorId === userId) {
                where += ` AND c.id =:creatorId `;
            } else {
                return res.badRequest('No rights!');
            }
        }

        // TODO: NOT THE MOST EFFICIENT QUERY IN THE WORLD, tune it when time.
        // TODO: That casting to "enum_TopicMemberUsers_level". Sequelize does not support naming enums, through inheritance I have 2 enums that are the same but with different name thus different type in PG. Feature request - https://github.com/sequelize/sequelize/issues/2577
        const query = `
                SELECT
                     t.id,
                     t.title,
                     t.description,
                     t.status,
                     t.visibility,
                     t.hashtag,
                     CASE
                     WHEN COALESCE(tmup.level, tmgp.level, 'none') = 'admin' THEN tj.token
                     ELSE NULL
                     END as "join.token",
                     CASE
                     WHEN COALESCE(tmup.level, tmgp.level, 'none') = 'admin' THEN tj.level
                     ELSE NULL
                     END as "join.level",
                     CASE
                        WHEN tp."topicId" = t.id THEN true
                        ELSE false
                     END as "pinned",
                     t.categories,
                     t."endsAt",
                     t."createdAt",
                     c.id as "creator.id",
                     c.name as "creator.name",
                     c.birthday as "creator.birthday",
                     COALESCE(tmup.level, tmgp.level, 'none') as "permission.level",
                     muc.count as "members.users.count",
                     COALESCE(mgc.count, 0) as "members.groups.count",
                     tv."voteId" as "voteId",
                     tv."voteId" as "vote.id",
                     CASE WHEN t.status = 'voting' THEN 1
                        WHEN t.status = 'inProgress' THEN 2
                        WHEN t.status = 'followUp' THEN 3
                     ELSE 4
                     END AS "order",
                     COALESCE(tc.count, 0) AS "comments.count",
                     com."createdAt" AS "comments.lastCreatedAt"
                    ${returncolumns}
                FROM "Topics" t
                    LEFT JOIN (
                        SELECT
                            tmu."topicId",
                            tmu."userId",
                            tmu.level::text AS level
                        FROM "TopicMemberUsers" tmu
                        WHERE tmu."deletedAt" IS NULL
                    ) AS tmup ON (tmup."topicId" = t.id AND tmup."userId" = :userId)
                    LEFT JOIN "TopicReports" tr ON  tr."topicId" = t.id
                    LEFT JOIN (
                        SELECT
                            tmg."topicId",
                            gm."userId",
                            MAX(tmg.level)::text AS level
                        FROM "TopicMemberGroups" tmg
                            LEFT JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                        WHERE tmg."deletedAt" IS NULL
                        AND gm."deletedAt" IS NULL
                        GROUP BY "topicId", "userId"
                    ) AS tmgp ON (tmgp."topicId" = t.id AND tmgp."userId" = :userId)
                    LEFT JOIN "Users" c ON (c.id = t."creatorId")
                    LEFT JOIN (
                        SELECT tmu."topicId", COUNT(tmu."memberId") AS "count" FROM (
                            SELECT
                                tmuu."topicId",
                                tmuu."userId" AS "memberId"
                            FROM "TopicMemberUsers" tmuu
                            WHERE tmuu."deletedAt" IS NULL
                            UNION
                            SELECT
                                tmg."topicId",
                                gm."userId" AS "memberId"
                            FROM "TopicMemberGroups" tmg
                                JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                                JOIN "Groups" g ON g.id = tmg."groupId"
                            WHERE tmg."deletedAt" IS NULL
                            AND g."deletedAt" IS NULL
                            AND gm."deletedAt" IS NULL
                        ) AS tmu GROUP BY "topicId"
                    ) AS muc ON (muc."topicId" = t.id)
                    LEFT JOIN (
                        SELECT
                            tmg."topicId",
                            count(tmg."groupId") AS "count"
                        FROM "TopicMemberGroups" tmg
                        JOIN "Groups" g ON (g.id = tmg."groupId")
                        WHERE tmg."deletedAt" IS NULL
                        AND g."deletedAt" IS NULL
                        GROUP BY tmg."topicId"
                    ) AS mgc ON (mgc."topicId" = t.id)
                    LEFT JOIN (
                        SELECT
                            tv."topicId",
                            tv."voteId",
                            v."authType",
                            v."createdAt",
                            v."delegationIsAllowed",
                            v."description",
                            v."endsAt",
                            v."reminderSent",
                            v."reminderTime",
                            v."maxChoices",
                            v."minChoices",
                            v."type",
                            v."autoClose"
                        FROM "TopicVotes" tv INNER JOIN
                            (
                                SELECT
                                    MAX("createdAt") as "createdAt",
                                    "topicId"
                                FROM "TopicVotes"
                                GROUP BY "topicId"
                            ) AS _tv ON (_tv."topicId" = tv."topicId" AND _tv."createdAt" = tv."createdAt")
                        LEFT JOIN "Votes" v
                                ON v.id = tv."voteId"
                    ) AS tv ON (tv."topicId" = t.id)
                    LEFT JOIN (
                        SELECT
                            "topicId",
                            COUNT(*) AS count
                        FROM "TopicComments"
                        GROUP BY "topicId"
                    ) AS tc ON (tc."topicId" = t.id)
                    LEFT JOIN (
                        SELECT
                            tcc."topicId",
                            MAX(tcc."createdAt") as "createdAt"
                            FROM
                                (SELECT
                                    tc."topicId",
                                    c."createdAt"
                                FROM "TopicComments" tc
                                JOIN "Comments" c ON c.id = tc."commentId"
                                GROUP BY tc."topicId", c."createdAt"
                                ORDER BY c."createdAt" DESC
                                ) AS tcc
                            GROUP BY tcc."topicId"
                    ) AS com ON (com."topicId" = t.id)
                    LEFT JOIN "TopicPins" tp ON (tp."topicId" = t.id AND tp."userId" = :userId)
                    LEFT JOIN "TopicJoins" tj ON (tj."topicId" = t.id AND tj."deletedAt" IS NULL)
                    ${join}
                WHERE ${where}
                ORDER BY "pinned" DESC, "order" ASC, t."updatedAt" DESC
            ;`;

        try {
            let rows;
            const rowsquery = db
                .query(
                    query,
                    {
                        replacements: {
                            userId: userId,
                            visibility: visibility,
                            statuses: statuses,
                            creatorId: creatorId
                        },
                        type: db.QueryTypes.SELECT,
                        raw: true,
                        nest: true
                    }
                );
            [rows, voteResults] = await Promise.all([rowsquery, voteResults]);
            const rowCount = rows.length;

            // Sequelize returns empty array for no results.
            const result = {
                count: rowCount,
                rows: []
            };

            if (rowCount > 0) {
                rows.forEach((topic) => {
                    topic.url = urlLib.getFe('/topics/:topicId', { topicId: topic.id });

                    if (include.indexOf('vote') > -1) {
                        if (topic.vote.id) {
                            const options = [];
                            if (topic.vote.options) {
                                topic.vote.options.forEach(function (voteOption) {
                                    const o = {};
                                    const optText = voteOption.split(':');
                                    o.id = optText[0];
                                    o.value = optText[1];
                                    let result = 0;
                                    if (voteResults && voteResults.length) {
                                        result = _.find(voteResults, { 'optionId': optText[0] });
                                        if (result) {
                                            o.voteCount = parseInt(result.voteCount, 10);
                                            if (result.selected) {
                                                o.selected = result.selected;
                                            }
                                        }
                                        topic.vote.votersCount = voteResults[0].votersCount;
                                    }

                                    options.push(o);
                                });
                            }
                            topic.vote.options = {
                                count: options.length,
                                rows: options
                            };
                        } else {
                            delete topic.vote;
                        }
                    }
                });
                result.rows = rows;
            }

            return res.ok(result);
        } catch (e) {
            return next(e);
        }
    });


    /**
     * Topic list
     */
    app.get('/api/topics', async function (req, res, next) {
        try {
            const limitMax = 500;
            const limitDefault = 26;
            let join = '';
            let groupBy = '';
            let returncolumns = '';
            let voteResults = false;
            let showModerated = req.query.showModerated || false;

            const offset = parseInt(req.query.offset, 10) ? parseInt(req.query.offset, 10) : 0;
            let limit = parseInt(req.query.limit, 10) ? parseInt(req.query.limit, 10) : limitDefault;

            if (limit > limitMax) limit = limitDefault;

            let statuses = req.query.statuses;
            if (statuses && !Array.isArray(statuses)) {
                statuses = [statuses];
            }

            let include = req.query.include;
            if (!Array.isArray(include)) {
                include = [include];
            }

            if (include) {
                if (include.indexOf('vote') > -1) {
                    returncolumns += `
                    , (
                        SELECT to_json(
                            array (
                                SELECT concat(id, ':', value)
                                FROM   "VoteOptions"
                                WHERE  "deletedAt" IS NULL
                                AND    "voteId" = tv."voteId"
                            )
                        )
                    ) as "vote.options"
                    , tv."voteId" as "vote.id"
                    , tv."authType" as "vote.authType"
                    , tv."createdAt" as "vote.createdAt"
                    , tv."delegationIsAllowed" as "vote.delegationIsAllowed"
                    , tv."description" as "vote.description"
                    , tv."endsAt" as "vote.endsAt"
                    , tv."maxChoices" as "vote.maxChoices"
                    , tv."minChoices" as "vote.minChoices"
                    , tv."type" as "vote.type"
                    `;
                    groupBy += `,tv."authType", tv."createdAt", tv."delegationIsAllowed", tv."description", tv."endsAt", tv."maxChoices", tv."minChoices", tv."type" `;
                    voteResults = getAllVotesResults();
                }
                if (include.indexOf('event') > -1) {
                    join += `LEFT JOIN (
                                SELECT
                                    COUNT(events.id) as count,
                                    events."topicId"
                                FROM "TopicEvents" events
                                WHERE events."deletedAt" IS NULL
                                GROUP BY events."topicId"
                            ) AS te ON te."topicId" = t.id
                    `;
                    returncolumns += `
                    , COALESCE(te.count, 0) AS "events.count"
                    `;
                    groupBy += `,te."count" `;
                }
            }

            let categories = req.query.categories;
            if (categories && !Array.isArray(categories)) {
                categories = [categories];
            }

            let where = ` t.visibility = '${Topic.VISIBILITY.public}'
                AND t.title IS NOT NULL
                AND t."deletedAt" IS NULL `;

            if (categories && categories.length) {
                where += ' AND t."categories" @> ARRAY[:categories]::VARCHAR(255)[] ';
            }

            if (!showModerated || showModerated == "false") {
                where += 'AND (tr."moderatedAt" IS NULL OR tr."resolvedAt" IS NOT NULL OR tr."deletedAt" IS NOT NULL) ';
            } else {
                where += 'AND tr."moderatedAt" IS NOT NULL AND tr."resolvedAt" IS NULL AND tr."deletedAt" IS NULL ';
            }

            if (statuses && statuses.length) {
                where += ' AND t.status IN (:statuses)';
            }

            const title = req.query.title;
            if (title) {
                where += ` AND t.title LIKE '%:title%' `;
            }

            const query = `
                    SELECT
                        t.id,
                        t.title,
                        t.description,
                        t.status,
                        t.visibility,
                        t.hashtag,
                        tj."token" AS "join.token",
                        tj."level" AS "join.level",
                        t.categories,
                        t."endsAt",
                        t."createdAt",
                        c.id as "creator.id",
                        c.name as "creator.name",
                        COALESCE(MAX(a."updatedAt"), t."updatedAt") as "lastActivity",
                        c.birthday as "creator.birthday",
                        muc.count as "members.users.count",
                        COALESCE(mgc.count, 0) as "members.groups.count",
                        CASE WHEN t.status = 'voting' THEN 1
                            WHEN t.status = 'inProgress' THEN 2
                            WHEN t.status = 'followUp' THEN 3
                        ELSE 4
                        END AS "order",
                        tv."voteId",
                        COALESCE(tc.count, 0) AS "comments.count",
                        COALESCE(com."createdAt", NULL) AS "comments.lastCreatedAt",
                        count(*) OVER()::integer AS "countTotal"
                        ${returncolumns}
                    FROM "Topics" t
                        LEFT JOIN "Users" c ON (c.id = t."creatorId")
                        LEFT JOIN "TopicReports" tr ON tr."topicId" = t.id
                        LEFT JOIN (
                            SELECT tmu."topicId", COUNT(tmu."memberId")::integer AS "count" FROM (
                                SELECT
                                    tmuu."topicId",
                                    tmuu."userId" AS "memberId"
                                FROM "TopicMemberUsers" tmuu
                                WHERE tmuu."deletedAt" IS NULL
                                UNION
                                SELECT
                                    tmg."topicId",
                                    gm."userId" AS "memberId"
                                FROM "TopicMemberGroups" tmg
                                    JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                                    JOIN "Groups" g ON g.id = tmg."groupId"
                                WHERE tmg."deletedAt" IS NULL
                                AND g."deletedAt" IS NULL
                                AND gm."deletedAt" IS NULL
                            ) AS tmu GROUP BY "topicId"
                        ) AS muc ON (muc."topicId" = t.id)
                        LEFT JOIN (
                            SELECT tmg."topicId", count(tmg."groupId")::integer AS "count"
                            FROM "TopicMemberGroups" tmg
                            JOIN "Groups" g
                                ON g.id = tmg."groupId"
                            WHERE tmg."deletedAt" IS NULL
                            AND g."deletedAt" IS NULL
                            GROUP BY tmg."topicId"
                        ) AS mgc ON (mgc."topicId" = t.id)
                        LEFT JOIN (
                            SELECT
                                "topicId",
                                COUNT(*)::integer AS count
                            FROM "TopicComments"
                            GROUP BY "topicId"
                        ) AS tc ON (tc."topicId" = t.id)
                        LEFT JOIN (
                            SELECT
                                tcc."topicId",
                                MAX(tcc."createdAt") as "createdAt"
                                FROM
                                    (SELECT
                                        tc."topicId",
                                        c."createdAt"
                                    FROM "TopicComments" tc
                                    JOIN "Comments" c ON c.id = tc."commentId"
                                    GROUP BY tc."topicId", c."createdAt"
                                    ORDER BY c."createdAt" DESC
                                    ) AS tcc
                                GROUP BY tcc."topicId"
                        ) AS com ON (com."topicId" = t.id)
                        LEFT JOIN (
                            SELECT
                                tv."topicId",
                                tv."voteId",
                                v."authType",
                                v."createdAt",
                                v."delegationIsAllowed",
                                v."description",
                                v."endsAt",
                                v."maxChoices",
                                v."minChoices",
                                v."type",
                                v."autoClose"
                            FROM "TopicVotes" tv INNER JOIN
                                (
                                    SELECT
                                        MAX("createdAt") as "createdAt",
                                        "topicId"
                                    FROM "TopicVotes"
                                    GROUP BY "topicId"
                                ) AS _tv ON (_tv."topicId" = tv."topicId" AND _tv."createdAt" = tv."createdAt")
                            LEFT JOIN "Votes" v
                                    ON v.id = tv."voteId"
                        ) AS tv ON (tv."topicId" = t.id)
                        LEFT JOIN "Activities" a ON ARRAY[t.id::text] <@ a."topicIds"
                        LEFT JOIN "TopicJoins" tj ON (tj."topicId" = t.id AND tj."deletedAt" IS NULL)
                        ${join}
                    WHERE ${where}
                    GROUP BY t.id, tj."token", tj.level, c.id, muc.count, mgc.count, tv."voteId", tc.count, com."createdAt"
                    ${groupBy}
                    ORDER BY "lastActivity" DESC
                    LIMIT :limit OFFSET :offset
                ;`;
            let topics;
            const topicsquery = db
                .query(
                    query,
                    {
                        replacements: {
                            categories: categories,
                            statuses: statuses,
                            limit: limit,
                            offset: offset
                        },
                        type: db.QueryTypes.SELECT,
                        raw: true,
                        nest: true
                    }
                );
            [topics, voteResults] = await Promise.all([topicsquery, voteResults]);
            if (!topics) {
                return res.notFound();
            }

            let countTotal = 0;
            if (topics && topics.length) {
                countTotal = topics[0].countTotal;
                topics.forEach(function (topic) {
                    topic.url = urlLib.getFe('/topics/:topicId', { topicId: topic.id });

                    delete topic.countTotal;

                    if (include && include.indexOf('vote') > -1 && topic.vote.id) {
                        const options = [];
                        if (topic.vote.options) {
                            topic.vote.options.forEach(function (voteOption) {
                                const o = {};
                                const optText = voteOption.split(':');
                                o.id = optText[0];
                                o.value = optText[1];
                                if (voteResults && voteResults.length) {
                                    const result = _.find(voteResults, { 'optionId': optText[0] });
                                    if (result) {
                                        o.voteCount = parseInt(result.voteCount, 10);
                                    }
                                    topic.vote.votersCount = voteResults[0].votersCount;
                                }
                                options.push(o);
                            });
                        }
                        topic.vote.options = {
                            count: options.length,
                            rows: options
                        };
                    } else {
                        delete topic.vote;
                    }
                });

            }

            // Sequelize returns empty array for no results.
            const result = {
                countTotal: countTotal,
                count: topics.length,
                rows: topics
            };

            return res.ok(result);
        } catch (e) {
            return next(e);
        }
    });

    const _getAllTopicMembers = async (topicId, userId, showExtraUserInfo) => {
        const response = {
            groups: {
                count: 0,
                rows: []
            },
            users: {
                count: 0,
                rows: []
            }
        };

        const groups = await db
            .query(
                `
                SELECT
                    g.id,
                    CASE
                        WHEN gmu.level IS NOT NULL THEN g.name
                        ELSE NULL
                    END as "name",
                    tmg.level,
                    gmu.level as "permission.level",
                    g.visibility,
                    gmuc.count as "members.users.count"
                FROM "TopicMemberGroups" tmg
                    JOIN "Groups" g ON (tmg."groupId" = g.id)
                    JOIN (
                        SELECT
                            "groupId",
                            COUNT(*) as count
                        FROM "GroupMemberUsers"
                        WHERE "deletedAt" IS NULL
                        GROUP BY 1
                    ) as gmuc ON (gmuc."groupId" = g.id)
                    LEFT JOIN "GroupMemberUsers" gmu ON (gmu."groupId" = g.id AND gmu."userId" = :userId AND gmu."deletedAt" IS NULL)
                WHERE tmg."topicId" = :topicId
                    AND tmg."deletedAt" IS NULL
                    AND g."deletedAt" IS NULL
                ORDER BY level DESC;`,
                {
                    replacements: {
                        topicId: topicId,
                        userId: userId
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true,
                    nest: true
                }
            );

        let extraUserInfo = '';
        if (showExtraUserInfo) {
            extraUserInfo = `
            u.email,
            uc."connectionData"::jsonb->>'phoneNumber' AS "phoneNumber",
            `;
        }

        const users = await db
            .query(
                `
                SELECT
                    tm.*
                FROM (
                    SELECT DISTINCT ON(id)
                        tm."memberId" as id,
                        tm."level",
                        tmu."level" as "levelUser",
                        u.name,
                        u.birthday,
                        ${extraUserInfo}
                        u."imageUrl"
                    FROM "Topics" t
                    JOIN (
                        SELECT
                            tmu."topicId",
                            tmu."userId" AS "memberId",
                            tmu."level"::text,
                            1 as "priority"
                        FROM "TopicMemberUsers" tmu
                        WHERE tmu."deletedAt" IS NULL
                        UNION
                        (
                            SELECT
                                tmg."topicId",
                                gm."userId" AS "memberId",
                                tmg."level"::text,
                                2 as "priority"
                            FROM "TopicMemberGroups" tmg
                            LEFT JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                            WHERE tmg."deletedAt" IS NULL
                            AND gm."deletedAt" IS NULL
                            ORDER BY tmg."level"::"enum_TopicMemberGroups_level" DESC
                        )
                    ) AS tm ON (tm."topicId" = t.id)
                    JOIN "Users" u ON (u.id = tm."memberId")
                    LEFT JOIN "TopicMemberUsers" tmu ON (tmu."userId" = tm."memberId" AND tmu."topicId" = t.id)
                    LEFT JOIN "UserConnections" uc ON (uc."userId" = tm."memberId" AND uc."connectionId" = 'esteid')
                    WHERE t.id = :topicId
                    ORDER BY id, tm.priority
                ) tm
                ORDER BY name ASC
                ;`,
                {
                    replacements: {
                        topicId: topicId
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true
                }
            );


        if (groups && groups.length) {
            response.groups.count = groups.length;
            response.groups.rows = groups;
        }

        if (users && users.length) {
            response.users.count = users.length;
            response.users.rows = users;
        }

        return response;
    };


    /**
     * Get all members of the Topic
     */
    app.get('/api/users/:userId/topics/:topicId/members', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read), async function (req, res, next) {
        try {
            const showExtraUserInfo = (req.user && req.user.moderator) || req.locals.topic.permissions.level === TopicMemberUser.LEVELS.admin;
            const response = await _getAllTopicMembers(req.params.topicId, req.user.userId, showExtraUserInfo);

            return res.ok(response);
        } catch (err) {
            return next(err);
        }
    });

    /**
     * Get all member Users of the Topic
     */
    app.get('/api/users/:userId/topics/:topicId/members/users', loginCheck(), isModerator(), hasPermission(TopicMemberUser.LEVELS.read), async function (req, res, next) {
        const limitDefault = 10;
        const offset = parseInt(req.query.offset, 10) ? parseInt(req.query.offset, 10) : 0;
        let limit = parseInt(req.query.limit, 10) ? parseInt(req.query.limit, 10) : limitDefault;
        const search = req.query.search;
        const order = req.query.order;
        let sortOrder = req.query.sortOrder || 'ASC';

        if (sortOrder && ['asc', 'desc'].indexOf(sortOrder.toLowerCase()) === -1) {
            sortOrder = 'ASC';
        }

        let sortSql = ` ORDER BY `;


        if (order) {
            switch (order) {
                case 'name':
                    sortSql += ` tm.name ${sortOrder} `;
                    break;
                case 'level':
                    sortSql += ` tm."level"::"enum_TopicMemberUsers_level" ${sortOrder} `;
                    break;
                default:
                    sortSql += ` tm.name ASC `
            }
        } else {
            sortSql += ` tm.name ASC `;
        }

        let where = '';
        if (search) {
            where = ` WHERE tm.name ILIKE :search `
        }

        let dataForModeratorAndAdmin = '';
        if ((req.user && req.user.moderator) || req.locals.topic.permissions.level === TopicMemberUser.LEVELS.admin) {
            dataForModeratorAndAdmin = `uc."connectionData"::jsonb->>'phoneNumber' AS "phoneNumber",`;
        }

        try {
            const users = await db
                .query(
                    `SELECT
                    tm.id,
                    tm.level,
                    tmu.level AS "levelUser",
                    tm.name,
                    tm.birthday,
                    tm."imageUrl",
                    ${dataForModeratorAndAdmin}
                    json_agg(
                        json_build_object('id', tmg."groupId",
                        'name', tmg.name,
                        'level', tmg."level"
                        )
                    ) as "groups.rows",
                    count(*) OVER()::integer AS "countTotal"
                FROM (
                    SELECT DISTINCT ON(id)
                        tm."memberId" as id,
                        tm."level",
                        u.name,
                        u.birthday,
                        u."imageUrl"
                    FROM "Topics" t
                    JOIN (
                        SELECT
                            tmu."topicId",
                            tmu."userId" AS "memberId",
                            tmu."level"::text,
                            1 as "priority"
                        FROM "TopicMemberUsers" tmu
                        WHERE tmu."deletedAt" IS NULL
                        UNION
                        SELECT
                            tmg."topicId",
                            gm."userId" AS "memberId",
                            tmg."level"::text,
                            2 as "priority"
                        FROM "TopicMemberGroups" tmg
                        LEFT JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                        WHERE tmg."deletedAt" IS NULL
                        AND gm."deletedAt" IS NULL
                    ) AS tm ON (tm."topicId" = t.id)
                    JOIN "Users" u ON (u.id = tm."memberId")
                    WHERE t.id = :topicId
                    ORDER BY id, tm.priority, tm."level"::"enum_TopicMemberUsers_level" DESC
                ) tm
                LEFT JOIN "TopicMemberUsers" tmu ON (tmu."userId" = tm.id AND tmu."topicId" = :topicId)
                LEFT JOIN (
                    SELECT gm."userId", tmg."groupId", tmg."topicId", tmg.level, g.name
                    FROM "GroupMemberUsers" gm
                    LEFT JOIN "TopicMemberGroups" tmg ON tmg."groupId" = gm."groupId"
                    LEFT JOIN "Groups" g ON g.id = tmg."groupId" AND g."deletedAt" IS NULL
                    WHERE gm."deletedAt" IS NULL
                    AND tmg."deletedAt" IS NULL
                ) tmg ON tmg."topicId" = :topicId AND (tmg."userId" = tm.id)
                LEFT JOIN "GroupMemberUsers" gmu ON (gmu."groupId" = tmg."groupId" AND gmu."userId" = :userId)
                LEFT JOIN "UserConnections" uc ON (uc."userId" = tm.id AND uc."connectionId" = 'esteid')
                ${where}
                GROUP BY tm.id, tm.level, tmu.level, tm.name, tm.birthday, tm."imageUrl", uc."connectionData"::jsonb
                ${sortSql}
                LIMIT :limit
                OFFSET :offset
                ;`,
                    {
                        replacements: {
                            topicId: req.params.topicId,
                            userId: req.user.userId,
                            search: '%' + search + '%',
                            limit,
                            offset
                        },
                        type: db.QueryTypes.SELECT,
                        raw: true,
                        nest: true
                    }
                )
            let countTotal = 0;
            if (users && users.length) {
                countTotal = users[0].countTotal;
            }
            users.forEach(function (userRow) {
                delete userRow.countTotal;

                userRow.groups.rows.forEach(function (group, index) {
                    if (group.id === null) {
                        userRow.groups.rows.splice(index, 1);
                    } else if (group.level === null) {
                        group.name = null;
                    }
                });
                userRow.groups.count = userRow.groups.rows.length;
            });

            return res.ok({
                countTotal,
                count: users.length,
                rows: users
            });
        } catch (err) {
            return next(err);
        }
    });

    /**
     * Get all member Groups of the Topic
     */
    app.get('/api/users/:userId/topics/:topicId/members/groups', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read), async function (req, res, next) {
        const limitDefault = 10;
        const offset = parseInt(req.query.offset, 10) ? parseInt(req.query.offset, 10) : 0;
        let limit = parseInt(req.query.limit, 10) ? parseInt(req.query.limit, 10) : limitDefault;
        const search = req.query.search;
        const order = req.query.order;
        let sortOrder = req.query.sortOrder || 'ASC';

        if (sortOrder && ['asc', 'desc'].indexOf(sortOrder.toLowerCase()) === -1) {
            sortOrder = 'ASC';
        }

        let sortSql = ` ORDER BY `;

        if (order) {
            switch (order) {
                case 'name':
                    sortSql += ` mg.name ${sortOrder} `;
                    break;
                case 'level':
                    sortSql += ` mg."level"::"enum_TopicMemberGroups_level" ${sortOrder} `;
                    break;
                case 'members.users.count':
                    sortSql += ` mg."members.users.count" ${sortOrder} `;
                    break;
                default:
                    sortSql = ` `
            }
        } else {
            sortSql = ` `;
        }

        let where = '';
        if (search) {
            where = `WHERE mg.name ILIKE :search`
        }

        try {
            const groups = await db
                .query(
                    `
                    SELECT mg.*,count(*) OVER()::integer AS "countTotal" FROM (
                        SELECT
                            g.id,
                            CASE
                                WHEN gmu.level IS NOT NULL THEN g.name
                                ELSE NULL
                            END as "name",
                            tmg.level,
                            gmu.level as "permission.level",
                            g.visibility,
                            gmuc.count as "members.users.count"
                        FROM "TopicMemberGroups" tmg
                            JOIN "Groups" g ON (tmg."groupId" = g.id)
                            JOIN (
                                SELECT
                                    "groupId",
                                    COUNT(*) as count
                                FROM "GroupMemberUsers"
                                WHERE "deletedAt" IS NULL
                                GROUP BY 1
                            ) as gmuc ON (gmuc."groupId" = g.id)
                            LEFT JOIN "GroupMemberUsers" gmu ON (gmu."groupId" = g.id AND gmu."userId" = :userId AND gmu."deletedAt" IS NULL)
                        WHERE tmg."topicId" = :topicId
                        AND tmg."deletedAt" IS NULL
                        AND g."deletedAt" IS NULL
                        ORDER BY level DESC
                    ) mg
                    ${where}
                    ${sortSql}
                    LIMIT :limit
                    OFFSET :offset;`,
                    {
                        replacements: {
                            topicId: req.params.topicId,
                            userId: req.user.userId,
                            search: `%${search}%`,
                            limit,
                            offset
                        },
                        type: db.QueryTypes.SELECT,
                        raw: true,
                        nest: true
                    }
                );

            let countTotal = 0;
            if (groups && groups.length) {
                countTotal = groups[0].countTotal;
            }
            groups.forEach(function (group) {
                delete group.countTotal;
            });

            return res.ok({
                countTotal,
                count: groups.length,
                rows: groups
            });
        } catch (err) {
            return next(err);
        }
    });

    const checkPermissionsForGroups = async function (groupIds, userId, level) {
        if (!Array.isArray(groupIds)) {
            groupIds = [groupIds];
        }

        const LEVELS = {
            none: 0, // Enables to override inherited permissions.
            read: 1,
            edit: 2,
            admin: 3
        };

        const minRequiredLevel = level || 'read';

        const result = await db
            .query(
                `
                SELECT
                    g.visibility = 'public' AS "isPublic",
                    gm."userId" AS "allowed",
                    gm."userId" AS uid,
                    gm."level" AS level,
                    g.id
                FROM "Groups" g
                LEFT JOIN "GroupMemberUsers" gm
                    ON(gm."groupId" = g.id)
                WHERE g.id IN (:groupIds)
                    AND gm."userId" = :userId
                    AND gm."deletedAt" IS NULL
                    AND g."deletedAt" IS NULL
                GROUP BY id, uid, level;`,
                {
                    replacements: {
                        groupIds: groupIds,
                        userId: userId,
                        level: minRequiredLevel
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true
                }
            )

        if (result && result.length) {
            if (result.length < groupIds.length) {
                return Promise.reject();
            }
            const checked = [];
            result.forEach((row) => {
                checked.push(
                    new Promise((reject, resolve) => {
                        const blevel = row.level;
                        if (LEVELS[minRequiredLevel] > LEVELS[blevel] && row.isPublic === true) {
                            logger.warn('Access denied to topic due to member without permissions trying to delete user! ', 'userId:', userId);

                            throw new Error('Access denied');
                        }
                        resolve();
                    })
                );
            });
            await Promise.all(checked)
                .catch((err) => {
                    if (err) {
                        return Promise.reject(err);
                    }
                });

            return result;
        } else {
            return Promise.reject();
        }
    };

    /**
     * Create new member Groups to a Topic
     */
    app.post('/api/users/:userId/topics/:topicId/members/groups', isSuperAdmin(), /*loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin, null, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]),*/ async function (req, res, next) {
        let members = req.body;
        const topicId = req.params.topicId;

        if (!Array.isArray(members)) {
            members = [members];
        }

        const groupIds = [];
        members.forEach(function (member) {
            groupIds.push(member.groupId);
        });
        try {
            const allowedGroups = await checkPermissionsForGroups(groupIds, req.user.userId, 'admin'); // Checks if all groups are allowed
            if (allowedGroups && allowedGroups[0]) {
                await db.transaction(async function (t) {

                    const topic = await Topic.findOne({
                        where: {
                            id: topicId
                        },
                        transaction: t
                    });

                    const findOrCreateTopicMemberGroups = allowedGroups.map(function (group) {
                        const member = _.find(members, function (o) {
                            return o.groupId === group.id;
                        });

                        return TopicMemberGroup
                            .findOrCreate({
                                where: {
                                    topicId: topicId,
                                    groupId: member.groupId
                                },
                                defaults: {
                                    level: member.level || TopicMemberUser.LEVELS.read
                                },
                                transaction: t
                            });
                    });

                    const groupIdsToInvite = [];
                    const memberGroupActivities = [];
                    await Promise
                        .allSettled(findOrCreateTopicMemberGroups)
                        .each(function (inspection) {
                            if (inspection.isFulfilled()) {
                                var memberGroup = inspection.value()[0].toJSON();
                                groupIdsToInvite.push(memberGroup.groupId);
                                const groupData = _.find(allowedGroups, function (item) {
                                    return item.id === memberGroup.groupId;
                                });
                                const group = Group.build(groupData);

                                const addActivity = cosActivities.addActivity(
                                    topic,
                                    {
                                        type: 'User',
                                        id: req.user.userId,
                                        ip: req.ip
                                    },
                                    null,
                                    group,
                                    req.method + ' ' + req.path,
                                    t
                                );
                                memberGroupActivities.push(addActivity);

                            } else {
                                logger.error('Adding Group failed', inspection.reason());
                            }
                        });
                    await Promise.all(memberGroupActivities);

                    t.afterCommit(() => {
                        return res.created();
                    });
                });
            } else {
                return res.forbidden();
            }

        } catch (err) {
            if (err) {
                if (err.message === 'Access denied') {
                    return res.forbidden();
                }
                logger.error('Adding Group to Topic failed', req.path, err);

                return next(err);
            }

            return res.forbidden();
        }
    });


    /**
     * Update User membership information
     */
    app.put('/api/users/:userId/topics/:topicId/members/users/:memberId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin, null, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]), async function (req, res, next) {
        const newLevel = req.body.level;
        const memberId = req.params.memberId;
        const topicId = req.params.topicId;

        try {
            const topicAdminMembers = await TopicMemberUser
                .findAll({
                    where: {
                        topicId: topicId,
                        level: TopicMemberUser.LEVELS.admin
                    },
                    attributes: ['userId'],
                    raw: true
                });
            const topicMemberUser = await TopicMemberUser.findOne({
                where: {
                    topicId: topicId,
                    userId: memberId
                }
            });

            if (topicAdminMembers && topicAdminMembers.length === 1 && _.find(topicAdminMembers, { userId: memberId })) {
                return res.badRequest('Cannot revoke admin permissions from the last admin member.');
            }

            // TODO: UPSERT - sequelize has "upsert" from new version, use that if it works - http://sequelize.readthedocs.org/en/latest/api/model/#upsert
            if (topicMemberUser) {
                await db.transaction(async function (t) {
                    topicMemberUser.level = newLevel;

                    await cosActivities.updateActivity(
                        topicMemberUser,
                        null,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );

                    await topicMemberUser.save({
                        transaction: t
                    });

                    t.afterCommit(() => {
                        return res.ok();
                    });
                });
            } else {
                await TopicMemberUser.create({
                    topicId: topicId,
                    userId: memberId,
                    level: newLevel
                });
                return res.ok();
            }
        } catch (e) {
            return next(e);
        }
    });


    /**
     * Update Group membership information
     */
    app.put('/api/users/:userId/topics/:topicId/members/groups/:memberId', isSuperAdmin(), /*loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin, null, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]),*/ async function (req, res, next) {
        const newLevel = req.body.level;
        const memberId = req.params.memberId;
        const topicId = req.params.topicId;

        try {
            let results;
            try {
                results = await checkPermissionsForGroups(memberId, req.user.userId);
            } catch (err) {
                return res.forbidden();
            }

            if (results && results[0] && results[0].id === memberId) {
                const topicMemberGroup = await TopicMemberGroup.findOne({
                    where: {
                        topicId: topicId,
                        groupId: memberId
                    }
                });

                await db.transaction(async function (t) {
                    topicMemberGroup.level = newLevel;

                    await cosActivities.updateActivity(
                        topicMemberGroup,
                        null,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );

                    await topicMemberGroup.save({ transaction: t });

                    t.afterCommit(() => res.ok());
                });
            } else {
                return res.forbidden();
            }

        } catch (err) {
            return next(err);
        }
    });


    /**
     * Delete User membership information
     */
    app.delete('/api/users/:userId/topics/:topicId/members/users/:memberId', isSuperAdmin(), async function (req, res, next) {
        const topicId = req.params.topicId;
        const memberId = req.params.memberId;
        try {
            const result = await TopicMemberUser.findAll({
                where: {
                    topicId: topicId,
                    level: TopicMemberUser.LEVELS.admin
                },
                attributes: ['userId'],
                raw: true
            });

            // At least 1 admin member has to remain at all times..
            if (result.length === 1 && _.find(result, { userId: memberId })) {
                return res.badRequest('Cannot delete the last admin member.', 10);
            }
            // TODO: Used to use TopicMemberUser.destroy, but that broke when moving 2.x->3.x - https://github.com/sequelize/sequelize/issues/4465
            // NOTE: Postgres does not support LIMIT for DELETE, thus the hidden "ctid" column and subselect is used
            const topicMemberUser = await db
                .query(
                    `SELECT
                        t.id as "Topic.id",
                        t.title as "Topic.title",
                        t.description as "Topic.description",
                        t.status as "Topic.status",
                        t.visibility as "Topic.visibility",
                        tj."token" as "Topic.join.token",
                        tj."level" as "Topic.join.level",
                        t.categories as "Topic.categories",
                        t."padUrl" as "Topic.padUrl",
                        t."endsAt" as "Topic.endsAt",
                        t.hashtag as "Topic.hashtag",
                        t."createdAt" as "Topic.createdAt",
                        t."updatedAt" as "Topic.updatedAt",
                        u.id as "User.id",
                        u.name as "User.name",
                        u.birthday as "User.birthday",
                        u.language as "User.language",
                        u.email as "User.email",
                        u."imageUrl" as "User.imageUrl"
                    FROM
                        "TopicMemberUsers" tmu
                    JOIN "Topics" t
                        ON t.id = tmu."topicId"
                    JOIN "TopicJoins" tj
                        ON (tj."topicId" = t.id AND tj."deletedAt" IS NULL)
                    JOIN "Users" u
                        ON u.id = tmu."userId"
                        WHERE
                        tmu."userId" = :userId
                        AND
                        tmu."topicId" = :topicId
                    ;`,
                    {
                        replacements: {
                            topicId: topicId,
                            userId: memberId
                        },
                        type: db.QueryTypes.SELECT,
                        raw: true,
                        nest: true
                    }
                );

            const topic = Topic.build(topicMemberUser.Topic);
            if (topic.status === Topic.STATUSES.closed && req.user.userId !== memberId) {
                return res.forbidden();
            }
            const user = User.build(topicMemberUser.User);
            topic.dataValues.id = topicId;
            user.dataValues.id = memberId;

            await db
                .transaction(async function (t) {
                    if (memberId === req.user.userId) {
                        // User leaving a Topic
                        logger.debug('Member is leaving the Topic', {
                            memberId: memberId,
                            topicId: topicId
                        });
                        await cosActivities
                            .leaveActivity(topic, {
                                type: 'User',
                                id: req.user.userId,
                                ip: req.ip
                            }, req.method + ' ' + req.path, t);
                    } else {
                        await cosActivities
                            .deleteActivity(user, topic, {
                                type: 'User',
                                id: req.user.userId,
                                ip: req.ip
                            }, req.method + ' ' + req.path, t);
                    }

                    await db
                        .query(
                            `
                            DELETE FROM
                                "TopicMemberUsers"
                            WHERE ctid IN (
                                SELECT
                                    ctid
                                FROM "TopicMemberUsers"
                                WHERE "topicId" = :topicId
                                    AND "userId" = :userId
                                LIMIT 1
                            )
                            `,
                            {
                                replacements: {
                                    topicId: topicId,
                                    userId: memberId
                                },
                                type: db.QueryTypes.DELETE,
                                transaction: t,
                                raw: true
                            }
                        );
                    t.afterCommit(() => {
                        return res.ok();
                    });
                });
        } catch (err) {
            return next(err);
        }
    });


    /**
     * Delete Group membership information
     */
    app.delete('/api/users/:userId/topics/:topicId/members/groups/:memberId', isSuperAdmin(), async function (req, res, next) {
        const topicId = req.params.topicId;
        const memberId = req.params.memberId;

        try {
            let results;
            try {
                results = await checkPermissionsForGroups(memberId, req.user.userId);
            } catch (err) {
                logger.error(err);

                return res.forbidden();
            }

            if (results && results[0] && results[0].id === memberId) {
                // TODO: Used to use TopicMemberGroups.destroy, but that broke when moving 2.x->3.x - https://github.com/sequelize/sequelize/issues/4465
                // NOTE: Postgres does not support LIMIT for DELETE, thus the hidden "ctid" column and subselect is used
                const topicMemberGroup = await db
                    .query(
                        `
                        SELECT
                            t.id as "Topic.id",
                            t.title as "Topic.title",
                            t.description as "Topic.description",
                            t.status as "Topic.status",
                            t.visibility as "Topic.visibility",
                            tj."token" as "Topic.join.token",
                            tj."level" as "Topic.join.level",
                            t.categories as "Topic.categories",
                            t."padUrl" as "Topic.padUrl",
                            t."endsAt" as "Topic.endsAt",
                            t.hashtag as "Topic.hashtag",
                            t."createdAt" as "Topic.createdAt",
                            t."updatedAt" as "Topic.updatedAt",
                            g.id as "Group.id",
                            g."parentId" as "Group.parentId",
                            g.name as "Group.name",
                            g."creatorId" as "Group.creator.id",
                            g.visibility as "Group.visibility"
                        FROM
                            "TopicMemberGroups" tmg
                        JOIN "Topics" t
                            ON t.id = tmg."topicId"
                        JOIN "TopicJoins" tj
                            ON (tj."topicId" = t.id AND tj."deletedAt" IS NULL)
                        JOIN "Groups" g
                            ON g.id = tmg."groupId"
                            WHERE
                            tmg."groupId" = :groupId
                            AND
                            tmg."topicId" = :topicId
                        ;`,
                        {
                            replacements: {
                                topicId: topicId,
                                groupId: memberId
                            },
                            type: db.QueryTypes.SELECT,
                            raw: true,
                            nest: true
                        }
                    );
                const topic = Topic.build(topicMemberGroup.Topic);
                topic.dataValues.id = topicId;
                const group = Group.build(topicMemberGroup.Group);
                group.dataValues.id = memberId;

                await db.transaction(async function (t) {
                    await cosActivities.deleteActivity(
                        group,
                        topic,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );

                    await db
                        .query(
                            `
                                DELETE FROM
                                    "TopicMemberGroups"
                                WHERE ctid IN (
                                    SELECT
                                        ctid
                                    FROM "TopicMemberGroups"
                                    WHERE "topicId" = :topicId
                                    AND "groupId" = :groupId
                                    LIMIT 1
                                )
                                `,
                            {
                                replacements: {
                                    topicId: topicId,
                                    groupId: memberId
                                },
                                type: db.QueryTypes.DELETE,
                                raw: true
                            }
                        );
                    t.afterCommit(() => res.ok());
                });
            } else {
                return res.forbidden();
            }

        } catch (err) {
            return next(err);
        }

    });

    /**
     * Invite new Members to the Topic
     *
     * Does NOT add a Member automatically, but will send an invite, which has to accept in order to become a Member of the Topic
     *
     * @see /api/users/:userId/topics/:topicId/members/users "Auto accept" - Adds a Member to the Topic instantly and sends a notification to the User.
     */
    app.post('/api/users/:userId/topics/:topicId/invites/users', loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin, false, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]), rateLimiter(5, false), speedLimiter(1, false), asyncMiddleware(async function (req, res) {
        const topicId = req.params.topicId;
        const userId = req.user.userId;
        let members = req.body;
        const MAX_LENGTH = 50;

        if (!Array.isArray(members)) {
            members = [members];
        }

        if (members.length > MAX_LENGTH) {
            return res.badRequest("Maximum user limit reached");
        }

        let validUserIdMembers = [];

        _(members).forEach(function (m) {
            if (m.userId) {
                m.userId = m.userId.trim();

                if (validator.isUUID(m.userId, 4)) {
                    validUserIdMembers.push(m);
                } else {
                    logger.warn('Invalid member ID, is not UUID thus ignoring', req.method, req.path, m, req.body);
                }
            } else {
                logger.warn('Missing member id, ignoring', req.method, req.path, m, req.body);
            }
        });

        const userGroupId = (await GroupMemberUser.findOne({where:{userId: userId}})).groupId;

        for (var i = 0; i < validUserIdMembers.length; i++) {
            const group = await GroupMemberUser.findOne({where:{userId: validUserIdMembers[i].userId}});
            const groupId = group ? group.groupId : false;
            if (groupId !== userGroupId) {
                return res.badRequest('Non puoi aggiungere utenti al di fuori del tuo gruppo.');
            }
        }

        await db.transaction(async function (t) {
            let createdUsers;

            // Need the Topic just for the activity
            const topic = await Topic.findOne({
                where: {
                    id: topicId
                }
            });

            validUserIdMembers = validUserIdMembers.filter(function (member) {
                return member.userId !== req.user.userId; // Make sure user does not invite self
            });

            const currentMembers = await TopicMemberUser.findAll({
                where: {
                    topicId: topicId
                }
            });

            const createInvitePromises = validUserIdMembers.map(async function (member) {
                const addedMember = currentMembers.find(function (cmember) {
                    return cmember.userId === member.userId;
                });
                if (addedMember) {
                    const LEVELS = {
                        none: 0, // Enables to override inherited permissions.
                        read: 1,
                        edit: 2,
                        admin: 3
                    };
                    if (addedMember.level !== member.level) {
                        if (LEVELS[member.level] > LEVELS[addedMember.level]) {
                            await addedMember.update({
                                level: member.level
                            });

                            cosActivities.updateActivity(
                                addedMember,
                                null,
                                {
                                    type: 'User',
                                    id: req.user.userId,
                                    ip: req.ip
                                },
                                req.method + ' ' + req.path,
                                t
                            );

                            return;
                        }

                        return;
                    } else {
                        return;
                    }
                } else {
                    const deletedCount = await TopicInviteUser
                        .destroy(
                            {
                                where: {
                                    userId: member.userId,
                                    topicId: topicId
                                }
                            }
                        );
                    logger.info(`Removed ${deletedCount} invites`);
                    const topicInvite = await TopicInviteUser.create(
                        {
                            topicId: topicId,
                            creatorId: userId,
                            userId: member.userId,
                            level: member.level
                        },
                        {
                            transaction: t
                        }
                    );

                    const userInvited = User.build({ id: topicInvite.userId });
                    userInvited.dataValues.level = topicInvite.level; // FIXME: HACK? Invite event, putting level here, not sure it belongs here, but.... https://github.com/citizenos/citizenos-fe/issues/112 https://github.com/w3c/activitystreams/issues/506
                    userInvited.dataValues.inviteId = topicInvite.id; // FIXME: HACK? Invite event, pu

                    await cosActivities.inviteActivity(
                        topic,
                        userInvited,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );

                    return topicInvite;
                }
            });

            let createdInvites = await Promise.all(createInvitePromises);

            createdInvites = createdInvites.filter(function (invite) {
                return !!invite;
            });

            await emailLib.sendTopicMemberUserInviteCreate(createdInvites);

            t.afterCommit(() => {
                if (createdInvites.length) {
                    return res.created({
                        count: createdInvites.length,
                        rows: createdInvites
                    });
                } else {
                    return res.badRequest('No invites were created. Possibly because no valid userId-s (uuidv4s) were provided.', 1);
                }
            });
        });
    }));

    app.get('/api/users/:userId/topics/:topicId/invites/users', loginCheck(), asyncMiddleware(async function (req, res) {
        const limitDefault = 10;
        const offset = parseInt(req.query.offset, 10) ? parseInt(req.query.offset, 10) : 0;
        let limit = parseInt(req.query.limit, 10) ? parseInt(req.query.limit, 10) : limitDefault;
        const search = req.query.search;

        const topicId = req.params.topicId;
        const userId = req.user.userId;
        const permissions = await _hasPermission(topicId, userId, TopicMemberUser.LEVELS.read, true);

        let where = '';
        if (search) {
            where = ` AND u.name ILIKE :search `
        }

        const order = req.query.order;
        let sortOrder = req.query.sortOrder || 'ASC';

        if (sortOrder && ['asc', 'desc'].indexOf(sortOrder.toLowerCase()) === -1) {
            sortOrder = 'ASC';
        }

        let sortSql = ` ORDER BY `;

        if (order) {
            switch (order) {
                case 'name':
                    sortSql += ` u.name ${sortOrder} `;
                    break;
                case 'level':
                    sortSql += ` tiu."level"::"enum_TopicInviteUsers_level" ${sortOrder} `;
                    break;
                default:
                    sortSql += ` u.name ASC `
            }
        } else {
            sortSql += ` u.name ASC `;
        }

        // User is not member and can only get own result
        if (!permissions) {
            where = ` AND tiu."userId" = :userId `;
        }

        const invites = await db
            .query(
                `SELECT
                        tiu.id,
                        tiu."creatorId",
                        tiu.level,
                        tiu."topicId",
                        tiu."userId",
                        tiu."expiresAt",
                        tiu."createdAt",
                        tiu."updatedAt",
                        u.id as "user.id",
                        u.name as "user.name",
                        u."imageUrl" as "user.imageUrl",
                        count(*) OVER()::integer AS "countTotal"
                    FROM "TopicInviteUsers" tiu
                    JOIN "Users" u ON u.id = tiu."userId"
                    LEFT JOIN "UserConnections" uc ON (uc."userId" = tiu."userId" AND uc."connectionId" = 'esteid')
                    WHERE tiu."topicId" = :topicId AND tiu."deletedAt" IS NULL AND tiu."expiresAt" > NOW()
                    ${where}
                    ${sortSql}
                    LIMIT :limit
                    OFFSET :offset
                    ;`,
                {
                    replacements: {
                        topicId,
                        limit,
                        offset,
                        userId,
                        search: `%${search}%`
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true,
                    nest: true
                }
            );

        if (!invites) {
            return res.notFound();
        }

        let countTotal = 0;

        if (invites.length) {
            countTotal = invites[0].countTotal;
        } else if (!permissions) {
            return res.forbidden('Non disponi dei permessi necessari a completare questa operazione.');
        }

        invites.forEach(function (invite) {
            delete invite.countTotal;
        });

        return res.ok({
            countTotal,
            count: invites.length,
            rows: invites
        });
    }));

    app.get(['/api/topics/:topicId/invites/users/:inviteId', '/api/users/:userId/topics/:topicId/invites/users/:inviteId'], asyncMiddleware(async function (req, res) {
        const topicId = req.params.topicId;
        const inviteId = req.params.inviteId;

        const invite = await TopicInviteUser
            .findOne({
                where: {
                    id: inviteId,
                    topicId: topicId
                },
                paranoid: false,
                include: [
                    {
                        model: Topic,
                        attributes: ['id', 'title', 'visibility', 'creatorId'],
                        as: 'topic',
                        required: true
                    },
                    {
                        model: User,
                        attributes: ['id', 'name', 'birthday', 'imageUrl'],
                        as: 'creator',
                        required: true
                    },
                    {
                        model: User,
                        attributes: ['id', 'password', 'source'],
                        as: 'user',
                        required: true,
                        include: [UserConnection]
                    }
                ],
                attributes: {
                    include: [
                        [
                            db.literal(`EXTRACT(DAY FROM (NOW() - "TopicInviteUser"."createdAt"))`),
                            'createdDaysAgo'
                        ]
                    ]
                }
            });

        if (!invite) {
            return res.notFound();
        }
        const hasAccess = await _hasPermission(topicId, invite.userId, TopicMemberUser.LEVELS.read, true);

        if (hasAccess) {
            return res.ok(invite, 1); // Invite has already been accepted OR deleted and the person has access
        }

        const invites = await TopicInviteUser
            .findAll(
                {
                    where: {
                        userId: invite.userId,
                        topicId: topicId
                    },
                    include: [
                        {
                            model: Topic,
                            attributes: ['id', 'title', 'visibility', 'creatorId'],
                            as: 'topic',
                            required: true
                        },
                        {
                            model: User,
                            attributes: ['id', 'name', 'birthday', 'imageUrl'],
                            as: 'creator',
                            required: true
                        },
                        {
                            model: User,
                            attributes: ['id', 'password', 'source'],
                            as: 'user',
                            required: true,
                            include: [UserConnection]
                        }
                    ],
                    attributes: {
                        include: [
                            [
                                db.literal(`EXTRACT(DAY FROM (NOW() - "TopicInviteUser"."createdAt"))`),
                                'createdDaysAgo'
                            ]
                        ]
                    }
                }
            );

        const levels = Object.keys(TopicMemberUser.LEVELS);
        const finalInvites = invites.filter((invite) => {
            if (invite.expiresAt > Date.now() && invite.deletedAt === null) {
                return invite;
            }
        }).sort((a, b) => {
            if (levels.indexOf(a.level) < levels.indexOf(b.level)) return 1;
            if (levels.indexOf(a.level) > levels.indexOf(b.level)) return -1;
            if (levels.indexOf(a.level) === levels.indexOf(b.level)) return 0;
        });

        if (!finalInvites.length) {
            if (invite.deletedAt) {
                return res.gone('The invite has been deleted', 1);
            }


            if (invite.expiresAt < Date.now()) {
                return res.gone(`The invite has expired. Invites are valid for ${TopicInviteUser.VALID_DAYS} days`, 2);
            }
        }

        // At this point we can already confirm users e-mail
        await User
            .update(
                {
                    emailIsVerified: true
                },
                {
                    where: { id: invite.userId },
                    fields: ['emailIsVerified'],
                    limit: 1
                }
            );

        // User has not been registered by a person but was created by the system on invite - https://github.com/citizenos/citizenos-fe/issues/773
        if (!invite.user.password && invite.user.source === User.SOURCES.citizenos && !invite.user.UserConnections.length) {
            return res.ok(finalInvites[0], 2);
        }

        return res.ok(finalInvites[0], 0);
    }));

    app.put(['/api/topics/:topicId/invites/users/:inviteId', '/api/users/:userId/topics/:topicId/invites/users/:inviteId'], loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin), asyncMiddleware(async function (req, res) {
        const newLevel = req.body.level;
        const topicId = req.params.topicId;
        const inviteId = req.params.inviteId;

        if (!(TopicMemberUser.LEVELS[newLevel])) {
            return res.badRequest(`Invalid level "${newLevel}"`)
        }

        const topicMemberUser = await TopicInviteUser
            .findOne(
                {
                    where: {
                        id: inviteId,
                        topicId: topicId
                    }
                }
            );

        if (topicMemberUser) {
            await db.transaction(async function (t) {
                topicMemberUser.level = newLevel;

                await cosActivities.updateActivity(
                    topicMemberUser,
                    null,
                    {
                        type: 'User',
                        id: req.user.userId,
                        ip: req.ip
                    },
                    req.method + ' ' + req.path,
                    t
                );

                await topicMemberUser.save({
                    transaction: t
                });

                t.afterCommit(() => {
                    return res.ok();
                });
            });
        } else {
            return res.notFound();
        }
    }));

    app.delete(['/api/topics/:topicId/invites/users/:inviteId', '/api/users/:userId/topics/:topicId/invites/users/:inviteId'], loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin), asyncMiddleware(async function (req, res) {
        const topicId = req.params.topicId;
        const inviteId = req.params.inviteId;
        const invite = await TopicInviteUser.findOne({
            where: {
                id: inviteId
            },
            paranoid: false
        });

        if (!invite) {
            return res.notFound('Invite not found', 1);
        }

        const deletedCount = await TopicInviteUser
            .destroy(
                {
                    where: {
                        userId: invite.userId,
                        topicId: topicId
                    }
                }
            );

        if (!deletedCount) {
            return res.notFound('Invite not found', 1);
        }

        return res.ok();
    }));

    app.post(['/api/users/:userId/topics/:topicId/invites/users/:inviteId/accept', '/api/topics/:topicId/invites/users/:inviteId/accept'], loginCheck(), asyncMiddleware(async function (req, res) {
        const userId = req.user.userId;
        const topicId = req.params.topicId;
        const inviteId = req.params.inviteId;

        const invite = await TopicInviteUser
            .findOne(
                {
                    where: {
                        id: inviteId,
                        topicId: topicId
                    },
                    attributes: {
                        include: [
                            [
                                db.literal(`EXTRACT(DAY FROM (NOW() - "TopicInviteUser"."createdAt"))`),
                                'createdDaysAgo'
                            ]
                        ]
                    },
                    paranoid: false
                }
            );

        if (invite && invite.userId !== userId) {
            return res.forbidden();
        }
        const invites = await TopicInviteUser
            .findAll(
                {
                    where: {
                        userId: invite.userId,
                        topicId: topicId
                    },
                    include: [
                        {
                            model: Topic,
                            attributes: ['id', 'title', 'visibility', 'creatorId'],
                            as: 'topic',
                            required: true
                        },
                        {
                            model: User,
                            attributes: ['id', 'name', 'birthday', 'imageUrl'],
                            as: 'creator',
                            required: true
                        },
                        {
                            model: User,
                            attributes: ['id', 'email', 'password', 'source'],
                            as: 'user',
                            required: true,
                            include: [UserConnection]
                        }
                    ],
                    attributes: {
                        include: [
                            [
                                db.literal(`EXTRACT(DAY FROM (NOW() - "TopicInviteUser"."createdAt"))`),
                                'createdDaysAgo'
                            ]
                        ]
                    }
                }
            );
        const levelsArray = Object.values(TopicMemberUser.LEVELS);
        const finalInvites = invites.filter((invite) => {
            if (invite.expiresAt > Date.now() && invite.deletedAt === null) {
                return invite;
            }
        }).sort((a, b) => {
            if (levelsArray.indexOf(a.level) < levelsArray.indexOf(b.level)) return 1;
            if (levelsArray.indexOf(a.level) > levelsArray.indexOf(b.level)) return -1;
            if (levelsArray.indexOf(a.level) === levelsArray.indexOf(b.level)) return 0;
        });
        const memberUserExisting = await TopicMemberUser
            .findOne({
                where: {
                    topicId: topicId,
                    userId: userId
                }
            });
        if (memberUserExisting) {
            // User already a member, see if we need to update the level
            if (finalInvites.length && levelsArray.indexOf(memberUserExisting.level) < levelsArray.indexOf(finalInvites[0].level)) {
                const memberUserUpdated = await memberUserExisting.update({
                    level: invite.level
                });
                return res.ok(memberUserUpdated);
            } else {
                // No level update, respond with existing member info
                return res.ok(memberUserExisting);
            }
        }

        if (!finalInvites.length) {
            // Find out if the User is already a member of the Topic
            if (invite.expiresAt < Date.now()) {
                return res.gone(`The invite has expired. Invites are valid for ${TopicInviteUser.VALID_DAYS} days`, 2);
            }
            return res.notFound();
        }

        const finalInvite = finalInvites[0];
        // Has the invite expired?


        // Topic needed just for the activity
        const topic = await Topic.findOne({
            where: {
                id: finalInvite.topicId
            }
        });

        await db.transaction(async function (t) {
            const member = await TopicMemberUser.create(
                {
                    topicId: finalInvite.topicId,
                    userId: finalInvite.userId,
                    level: TopicMemberUser.LEVELS[finalInvite.level]
                },
                {
                    transaction: t
                }
            );

            await TopicInviteUser.destroy({
                where: {
                    topicId: finalInvite.topicId,
                    userId: finalInvite.userId
                },
                transaction: t
            });

            const user = User.build({ id: member.userId });
            user.dataValues.id = member.userId;

            await cosActivities.acceptActivity(
                finalInvite,
                {
                    type: 'User',
                    id: req.user.userId,
                    ip: req.ip
                },
                {
                    type: 'User',
                    id: finalInvite.creatorId
                },
                topic,
                req.method + ' ' + req.path,
                t
            );
            t.afterCommit(() => {
                return res.created(member);
            });
        });
    }));

    /**
     * Get PUBLIC Topic information for given token.
     * Returns 404 for PRIVATE Topic even if it exists.
     */
    app.get('/api/topics/join/:token', async function (req, res) {
        const token = req.params.token;

        const topicJoin = await TopicJoin.findOne({
            where: {
                token: token
            }
        });

        if (!topicJoin) {
            return res.notFound();
        }
        const topic = await _topicReadUnauth(topicJoin.topicId, null);

        if (!topic) {
            return res.notFound();
        }

        return res.ok(topic);
    });


    /**
     * Join authenticated User to Topic with a given token.
     *
     * Allows sharing of private join urls for example in forums, on conference screen...
     */
    app.post('/api/topics/join/:token', loginCheck(), asyncMiddleware(async function (req, res) {
        const token = req.params.token;
        const userId = req.user.userId;

        const topicJoin = await TopicJoin.findOne({
            where: {
                token: token
            }
        });

        if (!topicJoin) {
            return res.badRequest('Matching token not found', 1);
        }

        const topic = await Topic.findOne({
            where: {
                id: topicJoin.topicId
            }
        });

        await db.transaction(async function (t) {
            const [memberUser, created] = await TopicMemberUser.findOrCreate({ // eslint-disable-line
                where: {
                    topicId: topic.id,
                    userId: userId
                },
                defaults: {
                    level: topicJoin.level
                },
                transaction: t
            });

            if (created) {
                const user = await User.findOne({
                    where: {
                        id: userId
                    }
                });

                await cosActivities.joinActivity(
                    topic,
                    {
                        type: 'User',
                        id: user.id,
                        ip: req.ip,
                        level: topicJoin.level
                    },
                    req.method + ' ' + req.path,
                    t
                );
            }
            const authorIds = topic.authorIds;
            const authors = await User.findAll({
                where: {
                    id: authorIds
                },
                attributes: ['id', 'name'],
                raw: true
            });

            const resObject = topic.toJSON();

            resObject.authors = authors;
            resObject.url = urlLib.getFe('/topics/:topicId', { topicId: topic.id });
            t.afterCommit(() => {
                return res.ok(resObject);
            });
        });
    }));


    /**
     * Add Topic Attachment
     */
    app.post('/api/users/:userId/topics/:topicId/attachments/upload', loginCheck(), hasPermission(TopicMemberUser.LEVELS.edit, false, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]), async function (req, res, next) {
        const attachmentLimit = config.attachments.limit || 5;
        const topicId = req.params.topicId;
        try {
            const topic = await Topic.findOne({
                where: {
                    id: topicId
                },
                include: [Attachment]
            });

            if (!topic) {
                return res.badRequest('Matching topic not found', 1);
            }
            if (topic.Attachments && topic.Attachments.length >= attachmentLimit) {
                return res.badRequest('Topic attachment limit reached', 2);
            }

            let data = await cosUpload.upload(req, topicId);
            data.creatorId = req.user.id;
            let attachment = Attachment.build(data);

            await db.transaction(async function (t) {
                attachment = await attachment.save({ transaction: t });
                await TopicAttachment.create(
                    {
                        topicId: req.params.topicId,
                        attachmentId: attachment.id
                    },
                    {
                        transaction: t
                    }
                );
                await cosActivities.addActivity(
                    attachment,
                    {
                        type: 'User',
                        id: req.user.id,
                        ip: req.ip
                    },
                    null,
                    topic,
                    req.method + ' ' + req.path,
                    t
                );

                t.afterCommit(() => {
                    return res.created(attachment.toJSON());
                });
            });
        } catch (err) {
            if (err.type && (err.type === 'fileSize' || err.type === 'fileType')) {
                return res.forbidden(err.message)
            }
            next(err);
        }
    });

    app.post('/api/users/:userId/topics/:topicId/attachments', loginCheck(), hasPermission(TopicMemberUser.LEVELS.edit, false, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]), async function (req, res, next) {
        const topicId = req.params.topicId;
        const name = req.body.name;
        const type = req.body.type;
        const source = req.body.source;
        const size = req.body.size;
        let link = req.body.link;
        const attachmentLimit = config.attachments.limit || 5;
        if (source !== Attachment.SOURCES.upload && !link) {
            return res.badRequest('Missing attachment link');
        }
        if (!name) {
            return res.badRequest('Missing attachment name');
        }

        try {
            const topic = await Topic.findOne({
                where: {
                    id: topicId
                },
                include: [Attachment]
            });
            if (!topic) {
                return res.badRequest('Matching topic not found', 1);
            }
            if (topic.Attachments && topic.Attachments.length >= attachmentLimit) {
                return res.badRequest('Topic attachment limit reached', 2);
            }
            let urlObject;
            if (link) {
                urlObject = new URL(link);
            }

            let invalidLink = false;
            switch (source) {
                case Attachment.SOURCES.dropbox:
                    if (['www.dropbox.com', 'dropbox.com'].indexOf(urlObject.hostname) === -1) {
                        invalidLink = true;
                    }
                    break;
                case Attachment.SOURCES.googledrive:
                    if (urlObject.hostname.split('.').splice(-2).join('.') !== 'google.com') {
                        invalidLink = true;
                    }
                    break;
                case Attachment.SOURCES.onedrive:
                    if (urlObject.hostname !== '1drv.ms') {
                        invalidLink = true;
                    }
                    break;
                default:
                    return res.badRequest('Invalid link source');
            }

            if (invalidLink) {
                return res.badRequest('Invalid link source');
            }

            let attachment = Attachment.build({
                name: name,
                type: type,
                size: size,
                source: source,
                creatorId: req.user.userId,
                link: link
            });

            await db.transaction(async function (t) {
                attachment = await attachment.save({ transaction: t });
                await TopicAttachment.create(
                    {
                        topicId: req.params.topicId,
                        attachmentId: attachment.id
                    },
                    {
                        transaction: t
                    }
                );
                await cosActivities.addActivity(
                    attachment,
                    {
                        type: 'User',
                        id: req.user.userId,
                        ip: req.ip
                    },
                    null,
                    topic,
                    req.method + ' ' + req.path,
                    t
                );

                t.afterCommit(() => {
                    return res.ok(attachment.toJSON());
                });
            });
        } catch (err) {
            next(err);
        }
    });

    app.put('/api/users/:userId/topics/:topicId/attachments/:attachmentId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.edit, false, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp]), async function (req, res, next) {
        const newName = req.body.name;

        if (!newName) {
            return res.badRequest('Missing attachment name');
        }

        try {
            const attachment = await Attachment
                .findOne({
                    where: {
                        id: req.params.attachmentId
                    },
                    include: [Topic]
                });

            attachment.name = newName;

            await db
                .transaction(async function (t) {
                    const topic = attachment.Topics[0];
                    delete attachment.Topics;

                    await cosActivities.updateActivity(
                        attachment,
                        topic,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );

                    await attachment.save({
                        transaction: t
                    });

                    t.afterCommit(() => {
                        return res.ok(attachment.toJSON());
                    });
                });
        } catch (err) {
            return next(err);
        }
    });

    /**
     * Delete Topic Attachment
     */
    app.delete('/api/users/:userId/topics/:topicId/attachments/:attachmentId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.edit, false, [Topic.STATUSES.inProgress, Topic.STATUSES.voting, Topic.STATUSES.followUp], true), async function (req, res, next) {
        try {
            const attachment = await Attachment.findOne({
                where: {
                    id: req.params.attachmentId
                },
                include: [Topic]
            });

            await db
                .transaction(async function (t) {
                    const link = new URL(attachment.link);
                    if (attachment.source === Attachment.SOURCES.upload) {
                        await cosUpload.delete(link.pathname);
                    }
                    await cosActivities.deleteActivity(attachment, attachment.Topics[0], {
                        type: 'User',
                        id: req.user.userId,
                        ip: req.ip
                    }, req.method + ' ' + req.path, t);

                    await attachment.destroy({ transaction: t });

                    t.afterCommit(() => {
                        return res.ok();
                    });
                })
        } catch (err) {
            return next(err);
        }
    });

    const getTopicAttachments = async (topicId) => {
        return await db
            .query(
                `
                SELECT
                    a.id,
                    a.name,
                    a.size,
                    a.source,
                    a.type,
                    a.link,
                    a."createdAt",
                    c.id as "creator.id",
                    c.name as "creator.name"
                FROM "TopicAttachments" ta
                JOIN "Attachments" a ON a.id = ta."attachmentId"
                JOIN "Users" c ON c.id = a."creatorId"
                WHERE ta."topicId" = :topicId
                AND a."deletedAt" IS NULL
                ;
                `,
                {
                    replacements: {
                        topicId: topicId
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true,
                    nest: true
                }
            );
    }
    const topicAttachmentsList = async function (req, res, next) {
        try {
            const attachments = await getTopicAttachments(req.params.topicId);

            return res.ok({
                count: attachments.length,
                rows: attachments
            });
        } catch (err) {
            return next(err);
        }
    };

    app.get('/api/users/:userId/topics/:topicId/attachments', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true), topicAttachmentsList);
    app.get('/api/topics/:topicId/attachments', hasVisibility(Topic.VISIBILITY.public), topicAttachmentsList);

    const readAttachment = async function (req, res, next) {
        try {
            const attachment = await Attachment
                .findOne({
                    where: {
                        id: req.params.attachmentId
                    }
                });

            if (attachment && attachment.source === Attachment.SOURCES.upload && req.query.download) {
                const fileUrl = new URL(attachment.link);
                let filename = attachment.name;

                if (filename.split('.').length <= 1 || path.extname(filename) !== `.${attachment.type}`) {
                    filename += '.' + attachment.type;
                }

                const options = {
                    hostname: fileUrl.hostname,
                    path: fileUrl.pathname,
                    port: fileUrl.port
                };

                if (app.get('env') === 'development' || app.get('env') === 'test') {
                    options.rejectUnauthorized = false;
                }

                https
                    .get(options, function (externalRes) {
                        res.setHeader('content-disposition', 'attachment; filename=' + encodeURIComponent(filename));
                        externalRes.pipe(res);
                    })
                    .on('error', function (err) {
                        return next(err);
                    })
                    .end();
            } else {
                return res.ok(attachment.toJSON());
            }
        } catch (err) {
            return next(err);
        }
    };

    app.get('/api/users/:userId/topics/:topicId/attachments/:attachmentId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true), readAttachment);
    app.get('/api/topics/:topicId/attachments/:attachmentId', hasVisibility(Topic.VISIBILITY.public), readAttachment);

    const topicReportsCreate = async function (req, res, next) {
        try {
            const topicId = req.params.topicId;

            const activeReportsCount = await TopicReport
                .count({
                    where: {
                        topicId: topicId,
                        resolvedById: null
                    }
                });

            if (activeReportsCount) {
                return res.badRequest('Topic has already been reported. Only one active report is allowed at the time to avoid overloading the moderators', 1);
            }

            await db.transaction(async function (t) {
                const topicReport = await TopicReport
                    .create(
                        {
                            topicId: topicId,
                            type: req.body.type,
                            text: req.body.text,
                            creatorId: req.user.userId,
                            creatorIp: req.ip
                        },
                        {
                            transaction: t
                        }
                    );

                await emailLib.sendTopicReport(topicReport);

                t.afterCommit(() => {
                    return res.ok(topicReport);
                })
            });
        } catch (err) {
            return next(err);
        }
    };

    /**
     * Report a Topic
     *
     * @see https://github.com/citizenos/citizenos-api/issues/5
     */
    app.post(['/api/users/:userId/topics/:topicId/reports', '/api/topics/:topicId/reports'], loginCheck(), hasVisibility(Topic.VISIBILITY.public), topicReportsCreate);

    /**
     * Read Topic Report
     *
     * @see https://github.com/citizenos/citizenos-api/issues/5
     */
    app.get(['/api/topics/:topicId/reports/:reportId', '/api/users/:userId/topics/:topicId/reports/:reportId'], hasVisibility(Topic.VISIBILITY.public), hasPermissionModerator(), async function (req, res, next) {
        try {
            const topicReports = await db
                .query(
                    `
                        SELECT
                            tr."id",
                            tr."type",
                            tr."text",
                            tr."createdAt",
                            tr."creatorId" as "creator.id",
                            tr."moderatedById" as "moderator.id",
                            tr."moderatedReasonText",
                            tr."moderatedReasonType",
                            tr."moderatedAt",
                            t."id" as "topic.id",
                            t."title" as "topic.title",
                            t."description" as "topic.description",
                            t."updatedAt" as "topic.updatedAt"
                        FROM "TopicReports" tr
                        LEFT JOIN "Topics" t ON (t.id = tr."topicId")
                        WHERE tr.id = :id
                        AND t.id = :topicId
                        AND tr."deletedAt" IS NULL
                    ;`,
                    {
                        replacements: {
                            topicId: req.params.topicId,
                            id: req.params.reportId
                        },
                        type: db.QueryTypes.SELECT,
                        raw: true,
                        nest: true
                    }
                );

            const topicReport = topicReports[0];

            if (!topicReport) {
                return res.notFound();
            }

            return res.ok(topicReport);
        } catch (err) {
            return next(err);
        }
    });

    /**
     * Moderate a Topic - moderator approves a report, thus applying restrictions to the Topic
     */
    app.post(['/api/topics/:topicId/reports/:reportId/moderate', '/api/users/:userId/topics/:topicId/reports/:reportId/moderate'], hasVisibility(Topic.VISIBILITY.public), hasPermissionModerator(), async function (req, res, next) {
        const moderatedReasonType = req.body.type; // Delete reason type which is provided in case deleted/hidden by moderator due to a user report
        const moderatedReasonText = req.body.text; // Free text with reason why the comment was deleted/hidden
        try {
            const topic = await Topic.findOne({
                where: {
                    id: req.params.topicId
                }
            });

            let topicReportRead = await TopicReport.findOne({
                where: {
                    id: req.params.reportId,
                    topicId: req.params.topicId
                }
            });

            if (!topic || !topicReportRead) {
                return res.notFound();
            }

            if (topicReportRead.resolvedById) {
                return res.badRequest('Report has become invalid cause the report has been already resolved', 11);
            }

            if (topicReportRead.moderatedById) {
                return res.badRequest('Report has become invalid cause the report has been already moderated', 12);
            }

            await db
                .transaction(async function (t) {
                    topicReportRead.moderatedById = req.user.userId;
                    topicReportRead.moderatedAt = db.fn('NOW');
                    topicReportRead.moderatedReasonType = moderatedReasonType || ''; // HACK: If Model has "allowNull: true", it will skip all validators when value is "null"
                    topicReportRead.moderatedReasonText = moderatedReasonText || ''; // HACK: If Model has "allowNull: true", it will skip all validators when value is "null"
                    let topicReportSaved = await topicReportRead
                        .save({
                            transaction: t,
                            returning: true
                        });

                    // Pass on the Topic info we loaded, don't need to load Topic again.
                    await emailLib.sendTopicReportModerate(Object.assign(
                        {},
                        topicReportSaved.toJSON(),
                        {
                            topic: topic
                        }
                    ));

                    t.afterCommit(() => {
                        return res.ok(topicReportSaved);
                    });
                });
        } catch (err) {
            return next(err);
        }
    });

    /** Send a Topic report for review - User let's Moderators know that the violations have been corrected **/
    app.post(['/api/users/:userId/topics/:topicId/reports/:reportId/review', '/api/topics/:topicId/reports/:reportId/review'], loginCheck(), hasPermission(TopicMemberUser.LEVELS.read), async function (req, res, next) {
        const topicId = req.params.topicId;
        const reportId = req.params.reportId;
        const text = req.body.text;
        try {
            if (!text || text.length < 10 || text.length > 4000) {
                return res.badRequest(null, 1, { text: 'Parameter "text" has to be between 10 and 4000 characters' });
            }

            const topicReport = await TopicReport.findOne({
                where: {
                    topicId: topicId,
                    id: reportId
                }
            });

            if (!topicReport) {
                return res.notFound('Topic report not found');
            }

            await emailLib.sendTopicReportReview(topicReport, text);

            return res.ok();
        } catch (err) {
            return next(err);
        }
    });

    /**
     * Resolve a Topic report - mark the Topic report as fixed, thus lifting restrictions on the Topic
     * We don't require /reports/review request to be sent to enable Moderators to act proactively
     *
     * @see https://app.citizenos.com/en/topics/ac8b66a4-ca56-4d02-8406-5e19da73d7ce?argumentsPage=1
     */
    app.post(['/api/topics/:topicId/reports/:reportId/resolve', '/api/users/:userId/topics/:topicId/reports/:reportId/resolve'], hasVisibility(Topic.VISIBILITY.public), hasPermissionModerator(), async function (req, res, next) {
        const topicId = req.params.topicId;
        const reportId = req.params.reportId;
        try {
            const topicReport = await TopicReport
                .update(
                    {
                        resolvedById: req.user.userId,
                        resolvedAt: db.fn('NOW')
                    },
                    {
                        where: {
                            topicId: topicId,
                            id: reportId
                        },
                        returning: true
                    }
                );

            await emailLib.sendTopicReportResolve(topicReport[1][0]);

            return res.ok();
        } catch (err) {
            return next(err);
        }
    });

    /**
     * Create Topic Comment
     */
    app.post('/api/users/:userId/topics/:topicId/comments', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true), asyncMiddleware(async function (req, res) {
        let type = req.body.type;
        const parentId = req.body.parentId;
        const parentVersion = req.body.parentVersion;
        let subject = req.body.subject;
        const text = req.body.text;
        const edits = [
            {
                text: text,
                subject: subject,
                createdAt: (new Date()).toISOString(),
                type: type
            }
        ];

        if (parentId) {
            subject = null;
            type = Comment.TYPES.reply;
            edits[0].type = type;
        }

        let comment = Comment.build({
            type: type,
            subject: subject,
            text: text,
            parentId: parentId,
            creatorId: req.user.userId,
            edits: edits
        });

        if (parentVersion) {
            comment.parentVersion = parentVersion;
        }

        await db
            .transaction(async function (t) {
                await comment.save({ transaction: t });
                //comment.edits.createdAt = JSON.stringify(comment.createdAt);
                const topic = await Topic.findOne({
                    where: {
                        id: req.params.topicId
                    },
                    transaction: t
                });

                if (parentId) {
                    const parentComment = await Comment.findOne({
                        where: {
                            id: parentId
                        },
                        transaction: t
                    });

                    if (parentComment) {
                        await cosActivities
                            .replyActivity(
                                comment,
                                parentComment,
                                topic,
                                {
                                    type: 'User',
                                    id: req.user.userId,
                                    ip: req.ip
                                }
                                , req.method + ' ' + req.path,
                                t
                            );
                    } else {
                        return res.notFound();
                    }
                } else {
                    await cosActivities
                        .createActivity(
                            comment,
                            topic,
                            {
                                type: 'User',
                                id: req.user.userId,
                                ip: req.ip
                            },
                            req.method + ' ' + req.path,
                            t
                        );
                }

                await TopicComment
                    .create(
                        {
                            topicId: req.params.topicId,
                            commentId: comment.id
                        },
                        {
                            transaction: t
                        }
                    );

                const c = await db.query(
                    `
                            UPDATE "Comments"
                                SET edits = jsonb_set(edits, '{0,createdAt}', to_jsonb("createdAt"))
                                WHERE id = :commentId
                                RETURNING *;
                        `,
                    {
                        replacements: {
                            commentId: comment.id
                        },
                        type: db.QueryTypes.UPDATE,
                        raw: true,
                        nest: true,
                        transaction: t
                    }
                );

                c[0][0].edits.forEach(function (edit) {
                    edit.createdAt = new Date(edit.createdAt).toJSON();
                });

                const resComment = await Comment.build(c[0][0]);
                t.afterCommit(() => {
                    return res.created(resComment.toJSON());
                });
            });
    }));

    const topicCommentsList = async function (req, res, next) {
        const orderByValues = {
            rating: 'rating',
            popularity: 'popularity',
            date: 'date'
        };
        let userId = null;
        let orderByComments = '"createdAt" DESC';
        let orderByReplies = '"createdAt" ASC';
        let dataForModerator = '';
        if (req.user) {
            userId = req.user.userId;

            if (req.user.moderator) {
                dataForModerator = `
                , 'email', u.email
                , 'phoneNumber', uc."connectionData"::jsonb->>'phoneNumber'
                `;
            }
        }

        switch (req.query.orderBy) {
            case orderByValues.rating:
                orderByComments = `votes->'up'->'count' DESC, votes->'up'->'count' ASC, "createdAt" DESC`;
                orderByReplies = `votes->'up'->'count' DESC, votes->'up'->'count' ASC, "createdAt" ASC`;
                break;
            case orderByValues.popularity:
                orderByComments = `votes->'count' DESC, "createdAt" DESC`;
                orderByReplies = `votes->'count' DESC, "createdAt" ASC`;
                break;
            default:
            // Do nothing
        }
        const commentRelationSql = injectReplacements(`
            WITH RECURSIVE commentRelations AS (
                SELECT
                    c.id,
                    c.type::text,
                    jsonb_build_object('id', c."parentId",'version',c."parentVersion") as parent,
                    c.subject,
                    c.text,
                    pg_temp.editCreatedAtToJson(c.edits) as edits,
                    jsonb_build_object('id', u.id,'name',u.name, 'birthday', u.birthday ${dataForModerator}) as creator,
                    CASE
                        WHEN c."deletedById" IS NOT NULL THEN jsonb_build_object('id', c."deletedById", 'name', dbu.name )
                        ELSE jsonb_build_object('id', c."deletedById")
                    END as "deletedBy",
                    c."deletedReasonType"::text,
                    c."deletedReasonText",
                    jsonb_build_object('id', c."deletedByReportId") as report,
                    jsonb_build_object('up', jsonb_build_object('count', COALESCE(cvu.sum, 0), 'selected', COALESCE(cvus.selected, false)), 'down', jsonb_build_object('count', COALESCE(cvd.sum, 0), 'selected', COALESCE(cvds.selected, false)), 'count', COALESCE(cvu.sum, 0) + COALESCE(cvd.sum, 0)) as votes,
                    to_char(c."createdAt" at time zone 'UTC', :dateFormat) as "createdAt",
                    to_char(c."updatedAt" at time zone 'UTC', :dateFormat) as "updatedAt",
                    to_char(c."deletedAt" at time zone 'UTC', :dateFormat) as "deletedAt",
                    0 AS depth
                    FROM "Comments" c
                    LEFT JOIN "Users" u ON (u.id = c."creatorId")
                    LEFT JOIN "UserConnections" uc ON (u.id = uc."userId" AND uc."connectionId" = 'esteid')
                    LEFT JOIN "Users" dbu ON (dbu.id = c."deletedById")
                    LEFT JOIN (
                        SELECT SUM(value), "commentId" FROM "CommentVotes" WHERE value > 0 GROUP BY "commentId"
                    ) cvu ON (cvu."commentId" = c.id)
                    LEFT JOIN (
                        SELECT "commentId", value,  true AS selected FROM "CommentVotes" WHERE value > 0 AND "creatorId"=:userId
                    ) cvus ON (cvu."commentId"= cvus."commentId")
                    LEFT JOIN (
                        SELECT SUM(ABS(value)), "commentId" FROM "CommentVotes" WHERE value < 0 GROUP BY "commentId"
                    ) cvd ON (cvd."commentId" = c.id)
                    LEFT JOIN (
                        SELECT "commentId", true AS selected FROM "CommentVotes" WHERE value < 0 AND "creatorId"=:userId
                    ) cvds ON (cvd."commentId"= cvds."commentId")
                    WHERE c.id = $1
                UNION ALL
                SELECT
                    c.id,
                    c.type::text,
                    jsonb_build_object('id', c."parentId",'version',c."parentVersion") as parent,
                    c.subject,
                    c.text,
                    pg_temp.editCreatedAtToJson(c.edits) as edits,
                    jsonb_build_object('id', u.id,'name',u.name, 'birthday', u.birthday ${dataForModerator}) as creator,
                    CASE
                        WHEN c."deletedById" IS NOT NULL THEN jsonb_build_object('id', c."deletedById", 'name', dbu.name )
                        ELSE jsonb_build_object('id', c."deletedById")
                    END as "deletedBy",
                    c."deletedReasonType"::text,
                    c."deletedReasonText",
                    jsonb_build_object('id', c."deletedByReportId") as report,
                    jsonb_build_object('up', jsonb_build_object('count', COALESCE(cvu.sum, 0), 'selected', COALESCE(cvus.selected, false)), 'down', jsonb_build_object('count', COALESCE(cvd.sum, 0), 'selected', COALESCE(cvds.selected, false)), 'count', COALESCE(cvu.sum, 0) + COALESCE(cvd.sum, 0)) as votes,
                    to_char(c."createdAt" at time zone 'UTC', :dateFormat) as "createdAt",
                    to_char(c."updatedAt" at time zone 'UTC', :dateFormat) as "updatedAt",
                    to_char(c."deletedAt" at time zone 'UTC', :dateFormat) as "deletedAt",
                    commentRelations.depth + 1
                    FROM "Comments" c
                    JOIN commentRelations ON c."parentId" = commentRelations.id AND c.id != c."parentId"
                    LEFT JOIN "Users" u ON (u.id = c."creatorId")
                    LEFT JOIN "UserConnections" uc ON (u.id = uc."userId" AND uc."connectionId" = 'esteid')
                    LEFT JOIN "Users" dbu ON (dbu.id = c."deletedById")
                    LEFT JOIN (
                        SELECT SUM(value), "commentId" FROM "CommentVotes" WHERE value > 0 GROUP BY "commentId"
                    ) cvu ON (cvu."commentId" = c.id)
                    LEFT JOIN (
                        SELECT "commentId", value, true AS selected FROM "CommentVotes" WHERE value > 0 AND "creatorId" = :userId
                    ) cvus ON (cvus."commentId" = c.id)
                    LEFT JOIN (
                        SELECT SUM(ABS(value)), "commentId" FROM "CommentVotes" WHERE value < 0 GROUP BY "commentId"
                    ) cvd ON (cvd."commentId" = c.id)
                    LEFT JOIN (
                        SELECT "commentId", true AS selected FROM "CommentVotes" WHERE value < 0 AND "creatorId" = :userId
                    ) cvds ON (cvds."commentId"= c.id)
            ),`, Sequelize.postgres, {
            userId: userId,
            dateFormat: 'YYYY-MM-DDThh24:mi:ss.msZ',
        }
        );

        const query = `
            CREATE OR REPLACE FUNCTION pg_temp.editCreatedAtToJson(jsonb)
                RETURNS jsonb
                AS $$ SELECT array_to_json(array(SELECT jsonb_build_object('subject', r.subject, 'text', r.text,'createdAt', to_char(r."createdAt" at time zone 'UTC', 'YYYY-MM-DDThh24:mi:ss.msZ'), 'type', r.type) FROM jsonb_to_recordset($1) as r(subject text, text text, "createdAt" timestamptz, type text)))::jsonb
            $$
            LANGUAGE SQL;

            CREATE OR REPLACE FUNCTION pg_temp.orderReplies(json)
                RETURNS json
                AS $$ SELECT array_to_json(array( SELECT row_to_json(r.*) FROM json_to_recordset($1)
                    AS
                    r(id uuid, type text, parent jsonb, subject text, text text, edits jsonb, creator jsonb, "deletedBy" jsonb, "deletedReasonType" text, "deletedReasonText" text, report jsonb, votes jsonb, "createdAt" text, "updatedAt" text, "deletedAt" text, replies jsonb)
                    GROUP BY r.*, r."createdAt", r.votes
                    ORDER BY ${orderByReplies}))
            $$
            LANGUAGE SQL;

            CREATE OR REPLACE FUNCTION pg_temp.getCommentTree(uuid)
                RETURNS TABLE(
                        "id" uuid,
                        type text,
                        parent jsonb,
                        subject text,
                        text text,
                        edits jsonb,
                        creator jsonb,
                        "deletedBy" jsonb,
                        "deletedReasonType" text,
                        "deletedReasonText" text,
                        report jsonb,
                        votes jsonb,
                        "createdAt" text,
                        "updatedAt" text,
                        "deletedAt" text,
                        replies jsonb)
                    AS $$

                        ${commentRelationSql}

                        maxdepth AS (
                            SELECT max(depth) maxdepth FROM commentRelations
                        ),

                        rootTree as (
                            SELECT c.* FROM
                                commentRelations c, maxdepth
                                WHERE depth = maxdepth
                            UNION ALL
                            SELECT c.* FROM
                                commentRelations c, rootTree
                                WHERE c.id = (rootTree.parent->>'id')::uuid AND rootTree.id != (rootTree.parent->>'id')::uuid
                        ),

                        commentTree AS (
                            SELECT
                                c.id,
                                c.type,
                                c.parent,
                                c.subject,
                                c.text,
                                pg_temp.editCreatedAtToJson(c.edits) as edits,
                                c.creator,
                                c."deletedBy",
                                c."deletedReasonType",
                                c."deletedReasonText",
                                c.report,
                                c.votes,
                                c."createdAt",
                                c."updatedAt",
                                c."deletedAt",
                                c.depth,
                                jsonb_build_object('count',0, 'rows', json_build_array()) replies
                                FROM commentRelations c, maxdepth
                                WHERE c.depth = maxdepth
                            UNION ALL
                            SELECT
                                (commentRelations).*,
                                jsonb_build_object('rows', pg_temp.orderReplies(array_to_json(
                                    array_cat(
                                        array_agg(commentTree)
                                        ,
                                        array(
                                            SELECT t
                                                FROM (
                                                    SELECT
                                                        l.*,
                                                        jsonb_build_object('count',0, 'rows', json_build_array()) replies
                                                    FROM commentRelations l, maxdepth
                                                        WHERE (l.parent->>'id')::uuid = (commentRelations).id
                                                        AND l.depth < maxdepth
                                                        AND l.id  NOT IN (
                                                            SELECT id FROM rootTree
                                                        )
                                                        ORDER BY l."createdAt" ASC
                                                ) r
                                            JOIN pg_temp.getCommentTree(r.id) t
                                                ON r.id = t.id
                                            ))
                                    )
                                ), 'count',
                                array_length((
                                    array_cat(
                                        array_agg(commentTree)
                                        ,
                                        array(
                                            SELECT t
                                                FROM (
                                                    SELECT
                                                        l.*
                                                    FROM commentRelations l, maxdepth
                                                        WHERE (l.parent->>'id')::uuid = (commentRelations).id
                                                        AND l.depth < maxdepth
                                                        AND l.id  NOT IN (
                                                            SELECT id FROM rootTree
                                                        )
                                                    ORDER BY l."createdAt" ASC
                                                ) r
                                            JOIN pg_temp.getCommentTree(r.id) t
                                                ON r.id = t.id
                                            ))
                                        ), 1)) replies
                    FROM (
                        SELECT commentRelations, commentTree
                            FROM commentRelations
                        JOIN commentTree
                            ON (
                                (commentTree.parent->>'id')::uuid = commentRelations.id
                                AND (commentTree.parent->>'id')::uuid != commentTree.id
                            )
                        ORDER BY commentTree."createdAt" ASC
                    ) v
                    GROUP BY v.commentRelations
                    )

                    SELECT
                        id,
                        type,
                        parent::jsonb,
                        subject,
                        text,
                        edits::jsonb,
                        creator::jsonb,
                        "deletedBy",
                        "deletedReasonType",
                        "deletedReasonText",
                        report,
                        votes::jsonb,
                        "createdAt",
                        "updatedAt",
                        "deletedAt",
                        replies::jsonb
                    FROM commentTree WHERE id = $1
                    ORDER BY ${orderByComments}
                $$
                LANGUAGE SQL;
                ;
        `;
        const selectSql = injectReplacements(`
            SELECT
                ct.id,
                ct.type,
                ct.parent,
                ct.subject,
                ct.text,
                ct.edits,
                ct.creator,
                ct."deletedBy",
                ct."deletedReasonType",
                ct."deletedReasonText",
                ct.report,
                ct.votes,
                ct."createdAt",
                ct."updatedAt",
                ct."deletedAt",
                ct.replies::jsonb
            FROM
                "TopicComments" tc
            JOIN "Comments" c ON c.id = tc."commentId" AND c.id = c."parentId"
            JOIN pg_temp.getCommentTree(tc."commentId") ct ON ct.id = ct.id
            WHERE tc."topicId" = :topicId
            ORDER BY ${orderByComments}
            LIMIT :limit
            OFFSET :offset
        `, Sequelize.postgres,
            {
                topicId: req.params.topicId,
                limit: parseInt(req.query.limit, 10) || 15,
                offset: parseInt(req.query.offset, 10) || 0
            }
        );

        try {
            const commentsQuery = db
                .query(`${query} ${selectSql}`,
                    {
                        type: db.QueryTypes.SELECT,
                        raw: true,
                        nest: true
                    }
                );
            const commentCountQuery = db
                .query(`
                        SELECT
                            c.type,
                            COUNT(c.type)
                        FROM "TopicComments" tc
                        JOIN "Comments" c ON tc."commentId" = c.id
                        WHERE tc."topicId" = :topicId
                        GROUP BY c.type;
                    `, {
                    replacements: {
                        topicId: req.params.topicId
                    }
                });
            const [comments, commentsCount] = await Promise.all([commentsQuery, commentCountQuery]);
            let countRes = {
                pro: 0,
                con: 0,
                poi: 0,
                reply: 0,
                total: 0
            }

            if (commentsCount.length) {
                commentsCount[0].forEach((item) => {
                    countRes[item.type] = item.count;
                });
            }
            countRes.total = countRes.pro + countRes.con + countRes.poi + countRes.reply;
            return res.ok({
                count: countRes,
                rows: comments
            });
        } catch (err) {
            return next(err);
        }
    };

    /**
     * Read (List) Topic Comments
     */
    app.get('/api/users/:userId/topics/:topicId/comments', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true), isModerator(), topicCommentsList);

    /**
     * Read (List) public Topic Comments
     */
    app.get('/api/topics/:topicId/comments', hasVisibility(Topic.VISIBILITY.public), isModerator(), topicCommentsList);

    /**
     * Delete Topic Comment
     */
    app.delete('/api/users/:userId/topics/:topicId/comments/:commentId', loginCheck(), isCommentCreator(), hasPermission(TopicMemberUser.LEVELS.admin, false, null, true));

    //WARNING: Don't mess up with order here! In order to use "next('route')" in the isCommentCreator, we have to have separate route definition
    //NOTE: If you have good ideas how to keep one route definition with several middlewares, feel free to share!
    app.delete('/api/users/:userId/topics/:topicId/comments/:commentId', asyncMiddleware(async function (req, res) {
        await db
            .transaction(async function (t) {
                const comment = await Comment.findOne({
                    where: {
                        id: req.params.commentId
                    },
                    include: [Topic]
                });

                comment.deletedById = req.user.userId;

                await comment.save({
                    transaction: t
                });

                await cosActivities
                    .deleteActivity(
                        comment,
                        comment.Topics[0],
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );
                await Comment
                    .destroy({
                        where: {
                            id: req.params.commentId
                        },
                        transaction: t
                    });
                t.afterCommit(() => res.ok());
            });
    }));

    app.put('/api/users/:userId/topics/:topicId/comments/:commentId', loginCheck(), isCommentCreator());

    //WARNING: Don't mess up with order here! In order to use "next('route')" in the isCommentCreator, we have to have separate route definition.
    //NOTE: If you have good ideas how to keep one route definition with several middlewares, feel free to share!
    app.put('/api/users/:userId/topics/:topicId/comments/:commentId', asyncMiddleware(async function (req, res) {
        const subject = req.body.subject;
        const text = req.body.text;
        let type = req.body.type;
        const commentId = req.params.commentId;

        const comment = await Comment.findOne({
            where: {
                id: commentId
            },
            include: [Topic]
        });
        const now = (new Date()).toISOString();
        const edits = comment.edits;

        if (text === comment.text && subject === comment.subject && type === comment.type) {
            return res.ok();
        }
        if (!type || comment.type === Comment.TYPES.reply) {
            type = comment.type;
        }
        edits.push({
            text: text,
            subject: subject,
            createdAt: now,
            type: type
        });
        comment.set('edits', null);
        comment.set('edits', edits);
        comment.subject = subject;
        comment.text = text;
        comment.type = type;

        await db
            .transaction(async function (t) {
                const topic = comment.Topics[0];
                delete comment.Topic;

                await cosActivities
                    .updateActivity(
                        comment,
                        topic,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );

                await comment.save({
                    transaction: t
                });

                // Sequelize somehow fails to replace inside jsonb_set
                await db
                    .query(`UPDATE "Comments"
                    SET edits = jsonb_set(edits, '{${comment.edits.length - 1}, createdAt }', to_jsonb("updatedAt"))
                    WHERE id = :commentId
                    RETURNING *;
                `,
                        {
                            replacements: {
                                commentId
                            },
                            type: db.QueryTypes.UPDATE,
                            raw: true,
                            nest: true,
                            transaction: t
                        });

                t.afterCommit(() => {
                    return res.ok();
                });
            });
    }));

    const topicCommentsReportsCreate = async function (req, res, next) {
        const commentId = req.params.commentId;
        try {
            const comment = await Comment.findOne({
                where: {
                    id: commentId
                }
            });

            if (!comment) {
                return comment;
            }

            await db
                .transaction(async function (t) {
                    const report = await Report
                        .create(
                            {
                                type: req.body.type,
                                text: req.body.text,
                                creatorId: req.user.userId,
                                creatorIp: req.ip
                            },
                            {
                                transaction: t
                            }
                        );
                    await cosActivities.addActivity(
                        report,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        null,
                        comment,
                        req.method + ' ' + req.path,
                        t
                    );
                    await CommentReport
                        .create(
                            {
                                commentId: commentId,
                                reportId: report.id
                            },
                            {
                                transaction: t
                            }
                        );
                    if (!report) {
                        return res.notFound();
                    }

                    await emailLib.sendCommentReport(commentId, report)

                    t.afterCommit(() => {
                        return res.ok(report);
                    });
                });
        } catch (err) {
            return next(err);
        }
    };

    app.post(['/api/users/:userId/topics/:topicId/comments/:commentId/reports', '/api/topics/:topicId/comments/:commentId/reports'], loginCheck(), topicCommentsReportsCreate);

    /**
     * Read Report
     */
    app.get(['/api/topics/:topicId/comments/:commentId/reports/:reportId', '/api/users/:userId/topics/:topicId/comments/:commentId/reports/:reportId'], authTokenRestrictedUse, asyncMiddleware(async function (req, res) {
        const results = await db
            .query(
                `
                        SELECT
                            r."id",
                            r."type",
                            r."text",
                            r."createdAt",
                            c."id" as "comment.id",
                            c.subject as "comment.subject",
                            c."text" as "comment.text"
                        FROM "Reports" r
                        LEFT JOIN "CommentReports" cr ON (cr."reportId" = r.id)
                        LEFT JOIN "Comments" c ON (c.id = cr."commentId")
                        WHERE r.id = :reportId
                        AND c.id = :commentId
                        AND r."deletedAt" IS NULL
                    ;`,
                {
                    replacements: {
                        commentId: req.params.commentId,
                        reportId: req.params.reportId
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true,
                    nest: true
                }
            );

        if (!results || !results.length) {
            return res.notFound();
        }

        const commentReport = results[0];

        return res.ok(commentReport);
    }));

    app.post('/api/topics/:topicId/comments/:commentId/reports/:reportId/moderate', authTokenRestrictedUse, asyncMiddleware(async function (req, res) {
        const eventTokenData = req.locals.tokenDecoded;
        const type = req.body.type;

        if (!type) {
            return res.badRequest({ type: 'Property type is required' });
        }

        const commentReport = (await db
            .query(
                `
                        SELECT
                            c."id" as "comment.id",
                            c."updatedAt" as "comment.updatedAt",
                            r."id" as "report.id",
                            r."createdAt" as "report.createdAt"
                        FROM "CommentReports" cr
                        LEFT JOIN "Reports" r ON (r.id = cr."reportId")
                        LEFT JOIN "Comments" c ON (c.id = cr."commentId")
                        WHERE cr."commentId" = :commentId AND cr."reportId" = :reportId
                        AND c."deletedAt" IS NULL
                        AND r."deletedAt" IS NULL
                    ;`,
                {
                    replacements: {
                        commentId: req.params.commentId,
                        reportId: req.params.reportId
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true,
                    nest: true
                }
            ))[0];

        if (!commentReport) {
            return res.notFound();
        }

        let comment = commentReport.comment;
        const report = commentReport.report;

        // If Comment has been updated since the Report was made, deny moderation cause the text may have changed.
        if (comment.updatedAt.getTime() > report.createdAt.getTime()) {
            return res.badRequest('Report has become invalid cause comment has been updated after the report', 10);
        }

        comment = await Comment.findOne({
            where: {
                id: comment.id
            },
            include: [Topic]
        });

        const topic = comment.dataValues.Topics[0];
        delete comment.dataValues.Topics;
        comment.deletedById = eventTokenData.userId;
        comment.deletedAt = db.fn('NOW');
        comment.deletedReasonType = req.body.type;
        comment.deletedReasonText = req.body.text;
        comment.deletedByReportId = report.id;

        await db
            .transaction(async function (t) {
                await cosActivities.updateActivity(
                    comment,
                    topic,
                    {
                        type: 'Moderator',
                        id: eventTokenData.userId,
                        ip: req.ip
                    },
                    req.method + ' ' + req.path,
                    t
                );

                let c = (await Comment.update(
                    {
                        deletedById: eventTokenData.userId,
                        deletedAt: db.fn('NOW'),
                        deletedReasonType: req.body.type,
                        deletedReasonText: req.body.text,
                        deletedByReportId: report.id
                    },
                    {
                        where: {
                            id: comment.id
                        },
                        returning: true
                    },
                    {
                        transaction: t
                    }
                ))[1];

                c = Comment.build(c.dataValues);

                await cosActivities
                    .deleteActivity(c, topic, {
                        type: 'Moderator',
                        id: eventTokenData.userId,
                        ip: req.ip
                    }, req.method + ' ' + req.path, t);

                t.afterCommit(() => {
                    return res.ok();
                });
            });
    }));


    /*
     * Read (List) Topic Comment votes
     */

    app.get('/api/users/:userId/topics/:topicId/comments/:commentId/votes', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true), async function (req, res, next) {
        try {
            const results = await db.query(
                `
                SELECT
                    u.name,
                    u.birthday,
                    u."imageUrl",
                    CAST(CASE
                        WHEN cv.value=1 Then 'up'
                        ELSE 'down' END
                    AS VARCHAR(5)) AS vote,
                    cv."createdAt",
                    cv."updatedAt"
                    FROM "CommentVotes" cv
                    LEFT JOIN "Users" u
                    ON
                        u.id = cv."creatorId"
                    WHERE cv."commentId" = :commentId
                    AND cv.value <> 0
                    ;
                `,
                {
                    replacements: {
                        commentId: req.params.commentId
                    },
                    type: db.QueryTypes.SELECT,
                    raw: true,
                    nest: true
                });

            return res.ok({
                rows: results,
                count: results.length
            });
        } catch (err) {
            return next(err);
        }
    });

    /**
     * Create a Comment Vote
     */
    app.post('/api/topics/:topicId/comments/:commentId/votes', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true), async function (req, res, next) {
        const value = parseInt(req.body.value, 10);
        try {
            const comment = await Comment
                .findOne({
                    where: {
                        id: req.params.commentId
                    }
                });

            if (!comment) {
                return comment;
            }

            await db
                .transaction(async function (t) {
                    const vote = await CommentVote
                        .findOne({
                            where: {
                                commentId: req.params.commentId,
                                creatorId: req.user.userId
                            },
                            transaction: t
                        });
                    if (vote) {
                        //User already voted
                        if (vote.value === value) { // Same value will 0 the vote...
                            vote.value = 0;
                        } else {
                            vote.value = value;
                        }
                        vote.topicId = req.params.topicId;

                        await cosActivities
                            .updateActivity(
                                vote,
                                comment,
                                {
                                    type: 'User',
                                    id: req.user.userId,
                                    ip: req.ip
                                },
                                req.method + ' ' + req.path,
                                t
                            );

                        await vote.save({ transaction: t });
                    } else {
                        //User has not voted...
                        const cv = await CommentVote
                            .create({
                                commentId: req.params.commentId,
                                creatorId: req.user.userId,
                                value: req.body.value
                            }, {
                                transaction: t
                            });
                        const c = _.cloneDeep(comment);
                        c.topicId = req.params.topicId;

                        await cosActivities
                            .createActivity(cv, c, {
                                type: 'User',
                                id: req.user.userId,
                                ip: req.ip
                            }, req.method + ' ' + req.path, t);
                    }

                    const results = await db
                        .query(
                            `
                            SELECT
                                tc."up.count",
                                tc."down.count",
                                COALESCE(cvus.selected, false) as "up.selected",
                                COALESCE(cvds.selected, false) as "down.selected"
                                FROM (
                                    SELECT
                                        tc."commentId",
                                        COALESCE(cvu.count, 0) as "up.count",
                                        COALESCE(cvd.count, 0) as "down.count"
                                    FROM "TopicComments" tc
                                        LEFT JOIN ( SELECT "commentId", COUNT(value) as count FROM "CommentVotes" WHERE value > 0 GROUP BY "commentId") cvu ON tc."commentId" = cvu."commentId"
                                        LEFT JOIN ( SELECT "commentId", COUNT(value) as count FROM "CommentVotes"  WHERE value < 0 GROUP BY "commentId") cvd ON tc."commentId" = cvd."commentId"
                                    WHERE tc."topicId" = :topicId
                                    AND tc."commentId" = :commentId
                                    GROUP BY tc."commentId", cvu.count, cvd.count
                                ) tc
                                LEFT JOIN (SELECT "commentId", "creatorId", value, true AS selected FROM "CommentVotes" WHERE value > 0 AND "creatorId" = :userId) cvus ON (tc."commentId" = cvus."commentId")
                                LEFT JOIN (SELECT "commentId", "creatorId", value, true AS selected FROM "CommentVotes" WHERE value < 0 AND "creatorId" = :userId) cvds ON (tc."commentId" = cvds."commentId");
                            `,
                            {
                                replacements: {
                                    topicId: req.params.topicId,
                                    commentId: req.params.commentId,
                                    userId: req.user.userId
                                },
                                type: db.QueryTypes.SELECT,
                                raw: true,
                                nest: true,
                                transaction: t
                            }
                        );

                    t.afterCommit(() => {
                        if (!results) {
                            return res.notFound();
                        }

                        return res.ok(results[0]);
                    });
                });

        } catch (err) {
            next(err);
        }
    });


    /**
     * Create a Vote
     */
    app.post('/api/users/:userId/topics/:topicId/votes', loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin, null, [Topic.STATUSES.inProgress]), asyncMiddleware(async function (req, res) {
        const voteOptions = req.body.options;

        if (!voteOptions || !Array.isArray(voteOptions) || voteOptions.length < 2) {
            return res.badRequest('Sono necessarie almeno 2 opzioni di voto.', 1);
        }

        const authType = Vote.AUTH_TYPES.soft;

        const vote = Vote.build({
            minChoices: req.body.minChoices || 1,
            maxChoices: req.body.maxChoices || 1,
            delegationIsAllowed: false,
            endsAt: req.body.endsAt,
            description: req.body.description,
            type: req.body.type || Vote.TYPES.regular,
            authType: authType,
            autoClose: req.body.autoClose,
            reminderTime: req.body.reminderTime
        });

        // TODO: Some of these queries can be done in parallel
        const topic = await Topic.findOne({
            where: {
                id: req.params.topicId
            }
        });

        await db
            .transaction(async function (t) {
                let voteOptionsCreated;

                await cosActivities
                    .createActivity(
                        vote,
                        null,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );
                await vote.save({ transaction: t });
                const voteOptionPromises = [];
                _(voteOptions).forEach(function (o) {
                    o.voteId = vote.id;
                    const vopt = VoteOption.build(o);
                    voteOptionPromises.push(vopt.validate());
                });

                await Promise.all(voteOptionPromises);
                voteOptionsCreated = await VoteOption
                    .bulkCreate(
                        voteOptions,
                        {
                            fields: ['id', 'voteId', 'value'], // Deny updating other fields like "updatedAt", "createdAt"...
                            returning: true,
                            transaction: t
                        }
                    );

                await cosActivities
                    .createActivity(
                        voteOptionsCreated,
                        null,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );
                await TopicVote
                    .create(
                        {
                            topicId: req.params.topicId,
                            voteId: vote.id
                        },
                        { transaction: t }
                    );
                await cosActivities
                    .createActivity(
                        vote,
                        topic,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );
                topic.status = Topic.STATUSES.voting;

                await cosActivities
                    .updateActivity(
                        topic,
                        null,
                        {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        },
                        req.method + ' ' + req.path,
                        t
                    );

                const resTopic = await topic
                    .save({
                        returning: true,
                        transaction: t
                    });

                vote.dataValues.VoteOptions = [];
                voteOptionsCreated.forEach(function (option) {
                    vote.dataValues.VoteOptions.push(option.dataValues);
                });

                t.afterCommit(() => {
                    return res.created(vote.toJSON());
                });
            });
    }));


    /**
     * Read a Vote
     */
    app.get('/api/users/:userId/topics/:topicId/votes/:voteId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true), asyncMiddleware(async function (req, res) {
        const topicId = req.params.topicId;
        const voteId = req.params.voteId;
        const userId = req.user.userId;

        const voteInfo = await Vote.findOne({
            where: { id: voteId },
            include: [
                {
                    model: Topic,
                    where: { id: topicId }
                },
                VoteOption,
                {
                    model: VoteDelegation,
                    where: {
                        voteId: voteId,
                        byUserId: userId
                    },
                    attributes: ['id'],
                    required: false,
                    include: [
                        {
                            model: User
                        }
                    ]
                }
            ]
        });

        if (!voteInfo) {
            return res.notFound();
        }

        const voteResults = await getVoteResults(voteId, userId);
        let hasVoted = false;
        if (voteResults && voteResults.length) {
            voteInfo.dataValues.VoteOptions.forEach(function (option) {
                const result = _.find(voteResults, { optionId: option.id });

                if (result) {
                    const voteCount = parseInt(result.voteCount, 10);
                    if (voteCount)
                        option.dataValues.voteCount = voteCount;//TODO: this could be replaced with virtual getters/setters - https://gist.github.com/pranildasika/2964211
                    if (result.selected) {
                        option.dataValues.selected = result.selected; //TODO: this could be replaced with virtual getters/setters - https://gist.github.com/pranildasika/2964211
                        hasVoted = true;
                    }
                }
            });

            voteInfo.dataValues.votersCount = voteResults[0].votersCount;
        }

        // TODO: Contains duplicate code with GET /status AND /sign
        if (hasVoted && voteInfo.authType === Vote.AUTH_TYPES.hard) {
            voteInfo.dataValues.downloads = { };
        }

        if (req.locals.topic.permissions.level === TopicMemberUser.LEVELS.admin && [Topic.STATUSES.followUp, Topic.STATUSES.closed].indexOf(req.locals.topic.status) > -1) {
            if (!voteInfo.dataValues.downloads) {
                voteInfo.dataValues.downloads = {};
            }
            const voteFinalURLParams = {
                userId: userId,
                topicId: topicId,
                voteId: voteId,
                type: 'final'
            };
        }

        return res.ok(voteInfo);
    }));

    /**
     * Update a Vote
     */
    app.put('/api/users/:userId/topics/:topicId/votes/:voteId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin), asyncMiddleware(async function (req, res) {
        const topicId = req.params.topicId;
        const voteId = req.params.voteId;

        // Make sure the Vote is actually related to the Topic through which the permission was granted.
        const fields = ['endsAt', 'reminderTime'];

        const topic = await Topic.findOne({
            where: {
                id: topicId
            },
            include: [
                {
                    model: Vote,
                    where: {
                        id: voteId
                    }
                }
            ]
        });

        if (!topic || !topic.Votes || !topic.Votes.length) {
            return res.notFound();
        }

        const vote = topic.Votes[0];

        await db.transaction(async function (t) {
            fields.forEach(function (field) {
                vote[field] = req.body[field];
            });

            await cosActivities
                .updateActivity(
                    vote,
                    topic,
                    {
                        type: 'User',
                        id: req.user.userId,
                        ip: req.ip
                    },
                    req.method + ' ' + req.path,
                    t
                );

            await vote.save({
                transaction: t
            });
            t.afterCommit(() => {
                return res.ok(vote.toJSON());
            })
        });
    }));

    /**
     * Read a public Topics Vote
     */
    app.get('/api/topics/:topicId/votes/:voteId', hasVisibility(Topic.VISIBILITY.public), asyncMiddleware(async function (req, res) {
        const topicId = req.params.topicId;
        const voteId = req.params.voteId;

        // TODO: Can be done in 1 query.
        const voteInfo = await Vote
            .findOne({
                where: { id: voteId },
                include: [
                    {
                        model: Topic,
                        where: { id: topicId }
                    },
                    VoteOption
                ]
            });

        if (!voteInfo) {
            return res.notFound();
        }

        const voteResults = await getVoteResults(voteId);
        if (voteResults && voteResults.length) {
            _(voteInfo.dataValues.VoteOptions).forEach(function (option) {
                const result = _.find(voteResults, { optionId: option.id });
                if (result) {
                    option.dataValues.voteCount = parseInt(result.voteCount, 10); //TODO: this could be replaced with virtual getters/setters - https://gist.github.com/pranildasika/2964211
                    if (result.selected) {
                        option.dataValues.selected = result.selected; //TODO: this could be replaced with virtual getters/setters - https://gist.github.com/pranildasika/2964211
                    }
                }
            });
            voteInfo.dataValues.votersCount = voteResults[0].votersCount;
        }

        return res.ok(voteInfo);
    }));

    const handleTopicVotePreconditions = async function (req, res) {
        const topicId = req.params.topicId;
        const voteId = req.params.voteId;

        if (!Array.isArray(req.body.options)) {
            return res.badRequest('Il parametro opzioni deve essere un array.');
        }

        let voteOptions = [...new Map(req.body.options.map(item => [item['optionId'], item])).values()];
        let isSingelOption = false;

        const vote = await Vote
            .findOne({
                where: { id: voteId },
                include: [
                    {
                        model: Topic,
                        where: { id: topicId }
                    },
                    {
                        model: VoteOption,
                        where: { id: _.map(voteOptions, 'optionId') },
                        required: false
                    }
                ]
            });

        if (!vote) {
            return res.notFound();
        }

        if (vote.endsAt && new Date() > vote.endsAt) {
            return res.badRequest('Le votazioni sono terminate.');
        }

        if (!vote.VoteOptions.length) {
            return res.badRequest('Opzioni di voto non valide.');
        }
        const singleOptions = _.filter(vote.VoteOptions, function (option) {
            const optVal = option.value.toLowerCase();

            return optVal === 'neutral' || optVal === 'veto';
        });
        if (singleOptions.length) {
            for (let i = 0; i < voteOptions.length; i++) {
                const isOption = _.find(singleOptions, function (opt) {
                    return opt.id === voteOptions[i].optionId;
                });

                if (isOption) {
                    isSingelOption = true;
                    req.body.options = [{ optionId: isOption.id }];
                }
            }
        }

        if (!isSingelOption && (voteOptions.length > vote.maxChoices || voteOptions.length < vote.minChoices)) {
            return res.badRequest('Le opzioni devono essere un array di minimo :minChoices e massimo :maxChoices elementi.'
                .replace(':minChoices', vote.minChoices)
                .replace(':maxChoices', vote.maxChoices));
        }

        return vote;
    };

    const _handleVoteAutoCloseConditions = async (voteId, topicId, userId) => {
        const vote = await Vote
            .findOne({
                where: { id: voteId },
                include: [
                    {
                        model: Topic,
                        where: { id: topicId }
                    }
                ]
            });

        if (vote.autoClose) {
            const promises = vote.autoClose.map(async (condition) => {
                if (condition.value === Vote.AUTO_CLOSE.allMembersVoted) {
                    const topicMembers = await _getAllTopicMembers(topicId, userId, false);
                    const voteResults = await getVoteResults(voteId, userId);
                    if (voteResults.length && topicMembers.users.count === voteResults[0].votersCount) {
                        vote.endsAt = (new Date()).toISOString();
                        await vote.save();

                        return true;
                    }
                }
            });
            const isClosed = await Promise.all(promises);

            return isClosed.includes(true);
        } else {
            return false;
        }
    };

    const handleVoteLists = async (req, userId, topicId, voteId, voteOptions, context, transaction) => {
        await VoteList.destroy({
            where: {
                voteId,
                userId
            },
            force: true,
            transaction: transaction
        });
        const voteListPromise = VoteList.bulkCreate(
            voteOptions,
            {
                fields: ['optionId', 'voteId', 'userId', 'optionGroupId', 'userHash'],
                transaction: transaction
            });
        const topicPromise = Topic.findOne({
            where: {
                id: topicId
            },
            transaction: transaction
        });
        const [voteList, topic] = await Promise.all([voteListPromise, topicPromise]);
        const vl = [];
        let tc = _.cloneDeep(topic.dataValues);
        tc.description = null;
        tc = Topic.build(tc);

        voteList.forEach(function (el, key) {
            delete el.dataValues.optionId;
            delete el.dataValues.optionGroupId;
            el = VoteList.build(el.dataValues);
            vl[key] = el;
        });
        const actor = {
            type: 'User',
            ip: req.ip
        };
        if (userId) {
            actor.id = userId;
        }
        const activityPromise = cosActivities.createActivity(vl, tc, actor, context, transaction);

        // Delete delegation if you are voting - TODO: why is this here? You cannot delegate when authType === 'hard'
        const destroyDelegation = VoteDelegation
            .destroy({
                where: {
                    voteId: voteId,
                    byUserId: userId
                },
                force: true,
                transaction: transaction
            });
        await Promise.all([activityPromise, destroyDelegation]);
    };

    const handleTopicVoteSoft = async function (vote, req, res, next) {
        try {
            const voteId = vote.id;
            const userId = req.user.userId;
            const topicId = req.params.topicId;

            if (!Array.isArray(req.body.options)) {
                return res.badRequest('Il parametro opzioni deve essere un array.');
            }

            const voteOptions = [...new Map(req.body.options.map(item => [item['optionId'], item])).values()];

            await db
                .transaction(async function (t) {
                    // Store vote options
                    const optionGroupId = Math.random().toString(36).substring(2, 10);

                    voteOptions.forEach((o) => {
                        o.voteId = voteId;
                        o.userId = userId;
                        o.optionGroupId = optionGroupId;
                    });

                    await handleVoteLists(req, userId, topicId, voteId, voteOptions, req.method + ' ' + req.path, t);
                    t.afterCommit(async () => {
                        const isClosed = await _handleVoteAutoCloseConditions(voteId, topicId, userId);
                        if (isClosed) {
                            return res.reload();
                        }

                        return res.ok();
                    });
                });
        } catch (err) {
            return next(err);
        }
    };

    const _checkAuthenticatedUser = async function (userId, personalInfo, transaction) {
        const userConnection = await UserConnection.findOne({
            where: {
                connectionId: {
                    [Op.in]: [
                        UserConnection.CONNECTION_IDS.esteid,
                        UserConnection.CONNECTION_IDS.smartid
                    ]
                },
                userId: userId
            },
            transaction
        });

        if (userConnection) {
            let personId = personalInfo.pid;
            let connectionUserId = userConnection.connectionUserId;
            if (personalInfo.pid.indexOf('PNO') > -1) {
                personId = personId.split('-')[1];
            }
            const country = (personalInfo.country || personalInfo.countryCode);
            const idPattern = `PNO${country}-${personId}`;
            if (connectionUserId.indexOf('PNO') > -1) {
                connectionUserId = connectionUserId.split('-')[1];
            }
            if (!userConnection.connectionData || (userConnection.connectionData.country || userConnection.connectionData.countryCode)) {
                if (userConnection.connectionUserId !== idPattern) {
                    throw new Error('User account already connected to another PID.');
                }
            }
            const conCountry = (userConnection.connectionData.country || userConnection.connectionData.countryCode)
            const connectionUserPattern = `PNO${conCountry}-${connectionUserId}`;
            if (connectionUserPattern !== idPattern) {
                throw new Error('User account already connected to another PID.');
            }
        }
    };

    /**
     * Vote
     *
     * IF Vote authType===hard then starts Vote signing process. Vote won't be counted before signing is finalized by calling POST /api/users/:userId/topics/:topicId/votes/:voteId/sign or Mobiil-ID signing is completed (GET /api/users/:userId/topics/:topicId/votes/:voteId/status)
     *
     * TODO: Should simplify all of this routes code. It's a mess cause I decided to keep one endpoint for all of the voting. Maybe it's a better idea to move authType===hard to separate endpont
     * TODO: create an alias /api/topics/:topicId/votes/:voteId for un-authenticated signing? I's weird to call /users/self when user has not logged in...
     */
    app.post('/api/users/:userId/topics/:topicId/votes/:voteId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true, [Topic.STATUSES.voting]), async function (req, res, next) {
        try {
            const vote = await handleTopicVotePreconditions(req, res);
            return handleTopicVoteSoft(vote, req, res, next);
        } catch (err) {
            return next(err);
        }
    });

    const handleHardVotingFinalization = async (req, userId, topicId, voteId, idSignFlowData, context, transaction) => {
        // Store vote options
        const voteOptions = idSignFlowData.voteOptions;
        const optionGroupId = Math.random().toString(36).substring(2, 10);

        let connectionUserId = idSignFlowData.personalInfo.pid;
        if (connectionUserId.indexOf('PNO') === -1) {
            const country = (idSignFlowData.personalInfo.country || idSignFlowData.personalInfo.countryCode);
            connectionUserId = `PNO${country}-${connectionUserId}`;
        }

        const userHash = createDataHash(voteId + connectionUserId);

        _(voteOptions).forEach(function (o) {
            o.voteId = voteId;
            o.userId = userId;
            o.optionGroupId = optionGroupId;
            o.optionId = o.optionId || o.id;
            o.userHash = userHash;
        });

        // Authenticated User signing, check the user connection
        if (req.user) {
            await _checkAuthenticatedUser(userId, idSignFlowData.personalInfo, transaction);
        }

        await handleVoteLists(req, userId, topicId, voteId, voteOptions, context, transaction);

        await UserConnection.upsert(
            {
                userId: userId,
                connectionId: UserConnection.CONNECTION_IDS.esteid,
                connectionUserId,
                connectionData: idSignFlowData.personalInfo
            },
            {
                transaction: transaction
            }
        );
    };

    /**
     * Delegate a Vote
     */
    app.post('/api/users/:userId/topics/:topicId/votes/:voteId/delegations', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, null, [Topic.STATUSES.voting]), async function (req, res, next) {
        const topicId = req.params.topicId;
        const voteId = req.params.voteId;

        const toUserId = req.body.userId;

        if (req.user.userId === toUserId) {
            return res.badRequest('Non puoi delegare te stesso.', 1);
        }

        const hasAccess = await _hasPermission(topicId, toUserId, TopicMemberUser.LEVELS.read, false, null, null);

        if (!hasAccess) {
            return res.badRequest('Cannot delegate Vote to User who does not have access to this Topic.', 2);
        }

        const vote = await Vote.findOne({
            where: {
                id: voteId
            },
            include: [
                {
                    model: Topic,
                    where: { id: topicId }
                }
            ]
        });
        if (!vote) {
            return res.notFound();
        }
        if (!vote.delegationIsAllowed) {
            return res.badRequest('La delega non è permessa per questo topic.', 2);
        }
        if (vote.endsAt && new Date() > vote.endsAt) {
            return res.badRequest('Le votazioni sono terminate.', 3);
        }

        try {
            await db.transaction(async function (t) {
                try {
                    let result = await db.query(`
                        WITH
                            RECURSIVE delegation_chains("voteId", "toUserId", "byUserId", depth) AS (
                                SELECT
                                    "voteId",
                                    "toUserId",
                                    "byUserId",
                                    1
                                FROM "VoteDelegations" vd
                                WHERE vd."voteId" = :voteId
                                    AND vd."byUserId" = :toUserId
                                    AND vd."deletedAt" IS NULL
                                UNION ALL
                                SELECT
                                    vd."voteId",
                                    vd."toUserId",
                                    dc."byUserId",
                                    dc.depth + 1
                                FROM delegation_chains dc, "VoteDelegations" vd
                                WHERE vd."voteId" = dc."voteId"
                                    AND vd."byUserId" = dc."toUserId"
                                    AND vd."deletedAt" IS NULL
                            ),
                            cyclicDelegation AS (
                                SELECT
                                    0
                                FROM delegation_chains
                                WHERE "byUserId" = :toUserId
                                    AND "toUserId" = :byUserId
                                LIMIT 1
                            ),
                            upsert AS (
                                UPDATE "VoteDelegations"
                                SET "toUserId" = :toUserId,
                                    "updatedAt" = CURRENT_TIMESTAMP
                                WHERE "voteId" = :voteId
                                AND "byUserId" = :byUserId
                                AND 1 = 1 / COALESCE((SELECT * FROM cyclicDelegation), 1)
                                AND "deletedAt" IS NULL
                                RETURNING *
                            )
                        INSERT INTO "VoteDelegations" ("voteId", "toUserId", "byUserId", "createdAt", "updatedAt")
                            SELECT :voteId, :toUserId, :byUserId, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                            WHERE NOT EXISTS (SELECT * FROM upsert)
                                AND 1 = 1 / COALESCE((SELECT * FROM cyclicDelegation), 1)
                        RETURNING *
                        ;`,
                        {
                            replacements: {
                                voteId: voteId,
                                toUserId: toUserId,
                                byUserId: req.user.userId
                            },
                            raw: true,
                            transaction: t
                        }
                    );
                    const delegation = VoteDelegation.build(result[0][0]);
                    await cosActivities
                        .createActivity(
                            delegation,
                            vote,
                            {
                                type: 'User',
                                id: req.user.userId,
                                ip: req.ip
                            },
                            req.method + ' ' + req.path,
                            t
                        );

                    t.afterCommit(() => {
                        return res.ok();
                    });
                } catch (err) {
                    // HACK: Forcing division by zero when cyclic delegation is detected. Cannot use result check as both update and cyclic return [].
                    if (err.parent.code === '22012') {
                        // Cyclic delegation detected.
                        return res.badRequest('Spiacente, non puoi delegare il tuo voto a questo utente.', 4);
                    }

                    // Don't hide other errors
                    throw err
                }
            });
        } catch (err) {
            return next(err);
        }
    });


    /**
     * Delete Vote delegation
     */
    app.delete('/api/users/:userId/topics/:topicId/votes/:voteId/delegations', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, null, [Topic.STATUSES.voting]), async function (req, res, next) {
        try {
            const topicId = req.params.topicId;
            const voteId = req.params.voteId;
            const userId = req.user.userId;

            const vote = await Vote
                .findOne({
                    where: { id: voteId },
                    include: [
                        {
                            model: Topic,
                            where: { id: topicId }
                        }
                    ]
                });

            if (!vote) {
                return res.notFound('Vote was not found for given topic', 1);
            }

            if (vote.endsAt && new Date() > vote.endsAt) {
                return res.badRequest('Le votazioni sono terminate.', 1);
            }

            const voteDelegation = await VoteDelegation
                .findOne({
                    where: {
                        voteId: voteId,
                        byUserId: userId
                    }
                });

            if (!voteDelegation) {
                return res.notFound('Delegation was not found', 2);
            }

            await db
                .transaction(async function (t) {
                    await cosActivities
                        .deleteActivity(
                            voteDelegation,
                            vote,
                            {
                                type: 'User',
                                id: req.user.userId,
                                ip: req.ip
                            },
                            req.method + ' ' + req.path,
                            t
                        );

                    await voteDelegation
                        .destroy({
                            force: true,
                            transaction: t
                        });

                    t.afterCommit(() => {
                        return res.ok();
                    });
                });
        } catch (err) {
            return next(err);
        }
    });

    const topicEventsCreate = async function (req, res, next) {
        const topicId = req.params.topicId;
        try {
            const topic = await Topic
                .findOne({
                    where: {
                        id: topicId
                    }
                });
            if (topic.status === Topic.STATUSES.closed) {
                return res.forbidden();
            }

            await db
                .transaction(async function (t) {
                    const event = await TopicEvent
                        .create(
                            {
                                topicId: topicId,
                                subject: req.body.subject,
                                text: req.body.text
                            },
                            {
                                transaction: t
                            }
                        );
                    const actor = {
                        type: 'User',
                        ip: req.ip
                    };

                    if (req.user && req.user.userId) {
                        actor.id = req.user.userId;
                    }

                    await cosActivities
                        .createActivity(
                            event,
                            topic,
                            actor,
                            req.method + ' ' + req.path,
                            t
                        );
                    t.afterCommit(() => {
                        return res.created(event.toJSON());
                    });
                });
        } catch (err) {
            return next(err);
        }

    };

    /** Create an Event **/
    app.post('/api/users/:userId/topics/:topicId/events', loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin, null, [Topic.STATUSES.followUp]), topicEventsCreate);


    /**
     * Create an Event with a token issued to a 3rd party
     */
    app.post('/api/topics/:topicId/events', authTokenRestrictedUse, topicEventsCreate);


    const topicEventsList = async function (req, res, next) {
        const topicId = req.params.topicId;
        try {
            const events = await TopicEvent
                .findAll({
                    where: {
                        topicId: topicId
                    },
                    order: [['createdAt', 'DESC']]
                });

            return res.ok({
                count: events.length,
                rows: events
            });
        } catch (err) {
            return next(err);
        }
    };


    /** List Events **/
    app.get('/api/users/:userId/topics/:topicId/events', loginCheck(), hasPermission(TopicMemberUser.LEVELS.read, true, [Topic.STATUSES.followUp, Topic.STATUSES.closed]), topicEventsList);


    /**
     * Read (List) public Topic Events
     */
    app.get('/api/topics/:topicId/events', hasVisibility(Topic.VISIBILITY.public), topicEventsList);


    /**
     * Delete event
     */
    app.delete('/api/users/:userId/topics/:topicId/events/:eventId', loginCheck(), hasPermission(TopicMemberUser.LEVELS.admin, null, [Topic.STATUSES.followUp]), async function (req, res, next) {
        const topicId = req.params.topicId;
        const eventId = req.params.eventId;
        try {
            const event = await TopicEvent.findOne({
                where: {
                    id: eventId,
                    topicId: topicId
                },
                include: [Topic]
            });

            await db
                .transaction(async function (t) {
                    await cosActivities
                        .deleteActivity(event, event.Topic, {
                            type: 'User',
                            id: req.user.userId,
                            ip: req.ip
                        }, req.method + ' ' + req.path, t);

                    await TopicEvent.destroy({
                        where: {
                            id: eventId,
                            topicId: topicId
                        },
                        transaction: t
                    });

                    t.afterCommit(() => {
                        return res.ok();
                    })
                });
        } catch (err) {
            return next(err);
        }
    });

    app.post('/api/users/:userId/topics/:topicId/pin', loginCheck(), async function (req, res, next) {
        const userId = req.user.userId;
        const topicId = req.params.topicId;

        try {
            await db
                .transaction(async function (t) {
                    await TopicPin.findOrCreate({
                        where: {
                            topicId: topicId,
                            userId: userId
                        },
                        transaction: t
                    });

                    t.afterCommit(() => {
                        return res.ok();
                    })
                });
        } catch (err) {
            return next(err);
        }
    });

    app.delete('/api/users/:userId/topics/:topicId/pin', loginCheck(), async function (req, res, next) {
        const userId = req.user.userId;
        const topicId = req.params.topicId;

        try {
            const topicPin = await TopicPin.findOne({
                where: {
                    userId: userId,
                    topicId: topicId
                }
            });

            if (topicPin) {
                await db
                    .transaction(async function (t) {
                        const topic = await Topic.findOne({
                            where: {
                                id: topicId
                            }
                        });

                        topic.description = null;

                        await TopicPin.destroy({
                            where: {
                                userId: userId,
                                topicId: topicId
                            },
                            transaction: t
                        });

                        t.afterCommit(() => {
                            return res.ok();
                        });
                    });
            }
        } catch (err) {
            return next(err);
        }
    });

    /**
    * Get User preferences LIST
   */
    app.get('/api/users/:userId/notificationsettings/topics', loginCheck(), async function (req, res, next) {
        try {
            const limitDefault = 10;
            const offset = parseInt(req.query.offset, 10) ? parseInt(req.query.offset, 10) : 0;
            let limit = parseInt(req.query.limit, 10) ? parseInt(req.query.limit, 10) : limitDefault;

            let title = req.query.search;
            let where = `t."deletedAt" IS NULL
                        AND t.title IS NOT NULL
                        AND COALESCE(tmup.level, tmgp.level, 'none')::"enum_TopicMemberUsers_level" > 'none' `;
            if (title) {
                title = `%${req.query.search}%`;
                where += ` AND t.title ILIKE :title `;
            }

            const query = `
                    SELECT
                         t.id AS "topicId",
                         t.title,
                         usn."allowNotifications",
                         usn."preferences",
                         count(*) OVER()::integer AS "countTotal"
                    FROM "Topics" t
                    LEFT JOIN (
                        SELECT
                            tmu."topicId",
                            tmu."userId",
                            tmu.level::text AS level
                        FROM "TopicMemberUsers" tmu
                        WHERE tmu."deletedAt" IS NULL
                    ) AS tmup ON (tmup."topicId" = t.id AND tmup."userId" = :userId)
                    LEFT JOIN (
                        SELECT
                            tmg."topicId",
                            gm."userId",
                            MAX(tmg.level)::text AS level
                        FROM "TopicMemberGroups" tmg
                            LEFT JOIN "GroupMemberUsers" gm ON (tmg."groupId" = gm."groupId")
                        WHERE tmg."deletedAt" IS NULL
                        AND gm."deletedAt" IS NULL
                        GROUP BY "topicId", "userId"
                    ) AS tmgp ON (tmgp."topicId" = t.id AND tmgp."userId" = :userId)
                    LEFT JOIN "UserNotificationSettings" usn ON usn."userId" = :userId AND usn."topicId" = t.id
                    WHERE ${where}
                    ORDER BY t."title" ASC
                    LIMIT :limit
                    OFFSET :offset
                ;`
            const userSettings = await db
                .query(
                    query,
                    {
                        replacements: {
                            userId: req.user.id,
                            title: title,
                            offset,
                            limit
                        },
                        type: db.QueryTypes.SELECT,
                        raw: true,
                        nest: true
                    }
                );
            let result = {
                count: 0,
                rows: []
            };
            if (userSettings.length) {
                result = {
                    count: userSettings[0].countTotal,
                    rows: userSettings
                };

            }

            return res.ok(result);
        } catch (err) {
            return next(err);
        }
    });

    /**
     * Get User Topic preferences
    */
    app.get('/api/users/:userId/topics/:topicId/notificationsettings', loginCheck(), asyncMiddleware(async function (req, res) {
        const userSettings = await UserNotificationSettings.findOne({
            where: {
                userId: req.user.id,
                topicId: req.params.topicId
            }
        });

        return res.ok(userSettings || {});
    }));

    /**
     * Set User preferences
    */
    app.put('/api/users/:userId/topics/:topicId/notificationsettings', loginCheck(), async function (req, res) {
        const settings = req.body;
        const allowedFields = ['topicId', 'allowNotifications', 'preferences'];
        const finalSettings = {};
        const topicId = req.params.topicId;
        const userId = req.user.id;

        Object.keys(settings).forEach((key) => {
            if (allowedFields.indexOf(key) > -1) finalSettings[key] = settings[key];
        });
        finalSettings.userId = userId;
        finalSettings.topicId = topicId;
        try {
            await db
                .transaction(async function (t) {
                    const topicPromise = Topic.findOne({
                        where: {
                            id: topicId
                        }
                    });
                    const userSettingsPromise = UserNotificationSettings.findOne({
                        where: {
                            userId,
                            topicId
                        }
                    });
                    let [userSettings, topic] = await Promise.all([userSettingsPromise, topicPromise]);
                    if (!userSettings) {
                        const savedSettings = await UserNotificationSettings.create(
                            finalSettings,
                            {
                                transaction: t
                            }
                        );
                        await cosActivities
                            .createActivity(savedSettings, topic, {
                                type: 'User',
                                id: req.user.userId,
                                ip: req.ip
                            }, req.method + ' ' + req.path, t);
                        userSettings = savedSettings;
                    } else {
                        userSettings.set(finalSettings);

                        await cosActivities
                            .updateActivity(userSettings, topic, {
                                type: 'User',
                                id: req.user.userId,
                                ip: req.ip
                            }, req.method + ' ' + req.path, t);

                        await userSettings.save({ transaction: t });
                    }
                    t.afterCommit(() => {
                        return res.ok(userSettings);
                    });
                });
        } catch (err) {
            console.log(err);
        }
    });

    /**
     * Delete User Topic preferences
    */
    app.delete('/api/users/:userId/topics/:topicId/notificationsettings', loginCheck(), asyncMiddleware(async function (req, res, next) {
        try {
            const topicPromise = Topic.findOne({
                where: {
                    id: req.params.topicId
                }
            });
            const userSettingsPromise = UserNotificationSettings.findOne({
                where: {
                    userId: req.user.id,
                    topicId: req.params.topicId
                }
            });
            let [userSettings, topic] = await Promise.all([userSettingsPromise, topicPromise]);

            await UserNotificationSettings.destroy({
                where: {
                    userId: req.user.id,
                    topicId: req.params.topicId
                },
                force: true
            });
            if (userSettings && topic) {
                await cosActivities.deleteActivity(userSettings, topic, {
                    type: 'User',
                    id: req.user.userId,
                    ip: req.ip
                }, req.method + ' ' + req.path,);
            }

            return res.ok();
        } catch (err) {
            return next(err);
        }
    }));

    return {
        hasPermission: hasPermission
    };
}
    ;

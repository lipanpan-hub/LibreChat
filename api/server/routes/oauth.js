// file deepcode ignore NoRateLimitingForLogin: Rate limiting is handled by the `loginLimiter` middleware
const express = require('express');
const passport = require('passport');
const { loginLimiter, checkBan, checkDomainAllowed } = require('~/server/middleware');
const { setAuthTokens, getFeiShuAccessToken, getFeiShuUserInfo } = require('~/server/services/AuthService');
const { logger } = require('~/config');
const { findUser, createUser, updateUser } = require('~/models/userMethods');

const router = express.Router();

const domains = {
  client: process.env.DOMAIN_CLIENT,
  server: process.env.DOMAIN_SERVER,
};

router.use(loginLimiter);

const oauthHandler = async (req, res) => {
  try {
    await checkDomainAllowed(req, res);
    await checkBan(req, res);
    if (req.banned) {
      return;
    }
    await setAuthTokens(req.user._id, res);
    res.redirect(domains.client);
  } catch (err) {
    logger.error('Error in setting authentication tokens:', err);
  }
};

const feishuOuthHandler = async (req, res) => {
  try {
    await checkDomainAllowed(req, res);
    await checkBan(req, res);
    if (req.banned) {
      return;
    }
    const data = await getFeiShuAccessToken(req.query.code);
    if (data.code == 0) {
      const userInfo = await getFeiShuUserInfo(data.data.access_token);
      let user = await findUser({ openidId: userInfo.data.open_id });
      if (!user) {
        user = {
          provider: 'openid',
          openidId: userInfo.data.open_id,
          username: userInfo.data.name,
          // email: userInfo.data.email,
          email: userInfo.data.enterprise_email,
          emailVerified: false,
          name: userInfo.data.name,
        };
        try {
          user = await createUser(user, true, true);
          logger.error('新增用户成功!');
        } catch(err) {
          logger.error('新增用户失败!', err);
        }
      } else {
        user.provider = 'openid';
        user.openidId = userInfo.data.open_id;
        user.username = userInfo.data.name;
        user.name = userInfo.data.name;
        try {
          user = await updateUser(user._id, user);
        } catch (err) {
          logger.error('更新用户失败!');
        }
        logger.info(
          `[openidStrategy] login success openidId: ${user.openidId} | email: ${user.email} | username: ${user.username} `,
          {
            user: {
              openidId: user.openidId,
              username: user.username,
              email: user.email,
              name: user.name,
            },
          },
        );
      };
      await setAuthTokens(user._id, res);
      res.redirect(domains.client);
    } else {
      logger.error('获取assess_token信息失败');
    }
  } catch (err) {
    logger.error('Error in setting authentication tokens:', err);
  }
};

/**
 * 飞书获取access_token
 */

/**
 * Google Routes
 */
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['openid', 'profile', 'email'],
    session: false,
  }),
);

router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${domains.client}/login`,
    failureMessage: true,
    session: false,
    scope: ['openid', 'profile', 'email'],
  }),
  oauthHandler,
);

router.get(
  '/facebook',
  passport.authenticate('facebook', {
    scope: ['public_profile'],
    profileFields: ['id', 'email', 'name'],
    session: false,
  }),
);

router.get(
  '/facebook/callback',
  passport.authenticate('facebook', {
    failureRedirect: `${domains.client}/login`,
    failureMessage: true,
    session: false,
    scope: ['public_profile'],
    profileFields: ['id', 'email', 'name'],
  }),
  oauthHandler,
);

router.get(
  '/openid',
  passport.authenticate('openid', {
    session: false,
  }),
);

// router.get(
//   '/openid/callback',
//   passport.authenticate('openid', {
//     failureRedirect: `${domains.client}/login`,
//     failureMessage: true,
//     session: false,
//   }),
//   oauthHandler,
// );

router.get(
  '/openid/callback',
  feishuOuthHandler,
);

router.get(
  '/github',
  passport.authenticate('github', {
    scope: ['user:email', 'read:user'],
    session: false,
  }),
);

router.get(
  '/github/callback',
  passport.authenticate('github', {
    failureRedirect: `${domains.client}/login`,
    failureMessage: true,
    session: false,
    scope: ['user:email', 'read:user'],
  }),
  oauthHandler,
);
router.get(
  '/discord',
  passport.authenticate('discord', {
    scope: ['identify', 'email'],
    session: false,
  }),
);

router.get(
  '/discord/callback',
  passport.authenticate('discord', {
    failureRedirect: `${domains.client}/login`,
    failureMessage: true,
    session: false,
    scope: ['identify', 'email'],
  }),
  oauthHandler,
);

module.exports = router;

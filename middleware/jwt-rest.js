// Copyright IBM Corp. 2014,2015. All Rights Reserved.
// Node module: loopback
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

/*!
 * Module dependencies.
 */

var async = require('async');
var g = require('strong-globalize')();
var assert = require('assert');
var debug = require('debug')('loopback:middleware:jwtrest');
var jwt = require('jwt-simple');

/*!
 * Export the middleware.
 */

module.exports = jwtRest;

/*
 * Rewrite the url to replace current user literal with the logged in user id
 */
function rewriteUserLiteral(req, currentUserLiteral) {
  if (req.accessToken && req.accessToken.userId && currentUserLiteral) {
    // Replace /me/ with /current-user-id/
    var urlBeforeRewrite = req.url;
    req.url = req.url.replace(
      new RegExp('/' + currentUserLiteral + '(/|$|\\?)', 'g'),
        '/' + req.accessToken.userId + '$1');
    if (req.url !== urlBeforeRewrite) {
      debug('req.url has been rewritten from %s to %s', urlBeforeRewrite,
        req.url);
    }
  }
}

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Check for an access token in cookies, headers, and query string parameters.
 * This function always checks for the following:
 *
 * - `access_token` (params only)
 * - `X-Access-Token` (headers only)
 * - `authorization` (headers and cookies)
 *
 * It checks for these values in cookies, headers, and query string parameters _in addition_ to the items
 * specified in the options parameter.
 *
 * **NOTE:** This function only checks for [signed cookies](http://expressjs.com/api.html#req.signedCookies).
 *
 * The following example illustrates how to check for an `accessToken` in a custom cookie, query string parameter
 * and header called `foo-auth`.
 *
 * ```js
 * app.use(loopback.token({
 *   cookies: ['foo-auth'],
 *   headers: ['foo-auth', 'X-Foo-Auth'],
 *   params: ['foo-auth', 'foo_auth']
 * }));
 * ```
 *
 * @options {Object} [options] Each option array is used to add additional keys to find an `accessToken` for a `request`.
 * @property {Array} [cookies] Array of cookie names.
 * @property {Array} [headers] Array of header names.
 * @property {Array} [params] Array of param names.
 * @property {Boolean} [searchDefaultTokenKeys] Use the default search locations for Token in request
 * @property {Boolean} [enableDoublecheck] Execute middleware although an instance mounted earlier in the chain didn't find a token
 * @property {Boolean} [overwriteExistingToken] only has effect in combination with `enableDoublecheck`. If truthy, will allow to overwrite an existing accessToken.
 * @property {Function|String} [model] AccessToken model name or class to use.
 * @property {String} [currentUserLiteral] String literal for the current user.
 * @header loopback.token([options])
 */

function tokenForRequest(req, options) {
  var params = options.params || [];
  var headers = options.headers || [];
  var cookies = options.cookies || [];
  var i = 0;
  var length, id;

  // https://github.com/strongloop/loopback/issues/1326
  if (options.searchDefaultTokenKeys !== false) {
    params = params.concat(['access_token']);
    headers = headers.concat(['X-Access-Token', 'authorization']);
    cookies = cookies.concat(['access_token', 'authorization']);
  }

  for (length = params.length; i < length; i++) {
    var param = params[i];
    // replacement for deprecated req.param()
    id = req.params && req.params[param] !== undefined ? req.params[param] :
      req.body && req.body[param] !== undefined ? req.body[param] :
      req.query && req.query[param] !== undefined ? req.query[param] :
      undefined;

    if (typeof id === 'string') {
      return id;
    }
  }

  for (i = 0, length = headers.length; i < length; i++) {
    id = req.header(headers[i]);

    if (typeof id === 'string') {
      // Add support for oAuth 2.0 bearer token
      // http://tools.ietf.org/html/rfc6750
      if (id.indexOf('Bearer ') === 0) {
        id = id.substring(7);
        // Decode from base64
        var buf = new Buffer(id, 'base64');
        id = buf.toString('utf8');
      } else if (/^Basic /i.test(id)) {
        id = id.substring(6);
        id = (new Buffer(id, 'base64')).toString('utf8');
        // The spec says the string is user:pass, so if we see both parts
        // we will assume the longer of the two is the token, so we will
        // extract "a2b2c3" from:
        //   "a2b2c3"
        //   "a2b2c3:"   (curl http://a2b2c3@localhost:3000/)
        //   "token:a2b2c3" (curl http://token:a2b2c3@localhost:3000/)
        //   ":a2b2c3"
        var parts = /^([^:]*):(.*)$/.exec(id);
        if (parts) {
          id = parts[2].length > parts[1].length ? parts[2] : parts[1];
        }
      }
      return id;
    }
  }

  if (req.signedCookies) {
    for (i = 0, length = cookies.length; i < length; i++) {
      id = req.signedCookies[cookies[i]];

      if (typeof id === 'string') {
        return id;
      }
    }
  }
  return null;
}

function jwtToken(options) {
  options = options || {};
  var secret = options.secret;

  var currentUserLiteral = options.currentUserLiteral;
  if (currentUserLiteral && (typeof currentUserLiteral !== 'string')) {
    debug('Set currentUserLiteral to \'me\' as the value is not a string.');
    currentUserLiteral = 'me';
  }
  if (typeof currentUserLiteral === 'string') {
    currentUserLiteral = escapeRegExp(currentUserLiteral);
  }

  var enableDoublecheck = !!options.enableDoublecheck;
  var overwriteExistingToken = !!options.overwriteExistingToken;

  return function(req, res, next) {
    var app = req.app;
    var registry = app.registry;

    if (req.accessToken !== undefined) {
      if (!enableDoublecheck) {
        // req.accessToken is defined already (might also be "null" or "false") and enableDoublecheck
        // has not been set --> skip searching for credentials
        rewriteUserLiteral(req, currentUserLiteral);
        return next();
      }
      if (req.accessToken && req.accessToken.id && !overwriteExistingToken) {
        // req.accessToken.id is defined, which means that some other middleware has identified a valid user.
        // when overwriteExistingToken is not set to a truthy value, skip searching for credentials.
        rewriteUserLiteral(req, currentUserLiteral);
        return next();
      }
      // continue normal operation (as if req.accessToken was undefined)
    }

    // JWT....
    var tokenId = tokenForRequest(req, options);
    if (tokenId) {
      try {
        var decodedToken = jwt.decode(tokenId, secret);
        req.accessToken = decodedToken || null;
        rewriteUserLiteral(req, currentUserLiteral);
        var ctx = req.loopbackContext;
        if (ctx && ctx.active) ctx.set('accessToken', decodedToken);
        next(null);
      }
      catch (e) {
        next(e);
      }
    } else {
      next(null);
    }
  };
}

/**
 * Expose models over REST.
 *
 * For example:
 * ```js
 * app.use(loopback.rest());
 * ```
 * For more information, see [Exposing models over a REST API](http://docs.strongloop.com/display/DOC/Exposing+models+over+a+REST+API).
 * @header loopback.rest()
 */

function jwtRest(options) {
  options = options || {};

  var handlers; // Cached handlers
  return function restApiHandler(req, res, next) {
    var app = req.app;
    var registry = app.registry;

    if (!handlers) {
      handlers = [];
      var remotingOptions = app.get('remoting') || {};

      var contextOptions = remotingOptions.context;
      if (contextOptions !== undefined && contextOptions !== false) {
        throw new Error(g.f(
          '%s was removed in version 3.0. See %s for more details.',
          'remoting.context option',
          'https://docs.strongloop.com/display/APIC/Using%20current%20context'));
      }

      if (app.isAuthEnabled) {
        handlers.push(jwtToken(options));
      }

      handlers.push(function(req, res, next) {
        // Need to get an instance of the REST handler per request
        return app.handler('rest')(req, res, next);
      });
    }
    if (handlers.length === 1) {
      return handlers[0](req, res, next);
    }
    async.eachSeries(handlers, function(handler, done) {
      handler(req, res, done);
    }, next);
  };
}
var parseUrl = require('url'),
  parseGitUrl = require('github-url-from-git'),
  Promise = require('bluebird'),
  _ = require('lodash'),
  request = require('request'),
  createGithubApi = require('./create-github-api.js'),
  Session = require('./session'),
  u = require('url');

var logger = console;

function AuthorizeGithub(opts) {
  _.extend(this, {
    packagePath: null, // required, name-spaced package name.
    token: null, // GitHub API Key.
    scope: null, // read, publish.
    debug: false,
    frontDoorHost: null,
    githubHost: null,
    githubOrg: null,
    untrustedPackageJson: null,
    githubPathPrefix: '/api/v3'
  }, require('@npm/enterprise-configurator').Config(), opts);
}

// Given a credentials object from the client,
// extract the pertinent parameters, and check
// authorization.
AuthorizeGithub.prototype.authorize = function(credentials, cb) {
  if (!credentials) return cb(null, false);
  logger.log('authorize with credentials', credentials);

  // path to package.json in front-door.
  this.packagePath = credentials.path;

  // on first publish we trust untrusted package.json.
  this.untrustedPackageJson = credentials.body;

  if (!credentials.headers.authorization || !credentials.headers.authorization.match(/Bearer /)) {
    return cb(null, false);
  }

  // Bearer token is the GHE auth token.
  // https://developers.google.com/gmail/actions/actions/verifying-bearer-tokens
  try {
    this.token = credentials.headers.authorization.replace('Bearer ', '');
  } catch (err) {
    logger.log('error parsing bearer token', err);
    return cb(null, false);
  }

  if (credentials.method == 'GET') {
    this.scope = 'read';
  } else if (credentials.method == 'PUT' || credentials.method === 'DELETE') {
    this.scope = 'publish';
  } else {
    return cb(Error('unsupported method'), null);
  }

  logger.log('attempting to authorize', this.scope)

  this.isAuthorized()
    .then(function(authorized) {
      logger.log('authorization response', authorized);
      cb(null, authorized);
    })
    .catch(function(err) {
      logger.log('authorization error', err);
      cb(err);
    });
};

// Given scope, auth-token, and package-name,
// returns whether or not a user is authorized
// to perform an action on a package.
AuthorizeGithub.prototype.isAuthorized = function() {
  var _this = this;

  return new Promise(function(resolve, reject) {
    _this.loadPackageJSON().then(function(packageJson) {
      return _this.parseGitUrl(packageJson);
    }).then(function(githubParams) {
      if (_this.githubOrg && githubParams.org !== _this.githubOrg && this.scope === 'publish') return reject(Error('invalid organization name'));

      var github = createGithubApi(_this);

      // setup github to use OAuth Access Token.
      github.authenticate({
        type: 'oauth',
        token: _this.token
      });

      var fallbackAuth = function() {
        logger.log('falling back to older auth');
        // if member of the master org and not a read then
        // check whether user is authorized for the scope provided.
        github.repos.get({user: githubParams.org, repo: githubParams.repo}, function(err, res) {
          if (err) {
            if (err.code == 404) return resolve(false);
            else return reject(err);
          }
          else return _this._handleGithubResponse(res, resolve, reject);
        });
      };

      // Check if authenticated user is a member of the master org if one is set
      logger.log('githuborg: ', _this.githubOrg);
      logger.log('scope: ', _this.scope);
      if (_this.githubOrg) {  // TODO: add another config setting to specifically enable this functionality
        github.users.getOrgs({}, function(err, res) {
          if (err) {
            return reject(err);
          } else {
            var isMemberOfMasterOrg = _.find(res, { login: _this.githubOrg }) === undefined ? false : true;
            logger.log('isMemberOfMasterOrg', isMemberOfMasterOrg);
            if (!isMemberOfMasterOrg) {
              return resolve(false);
            } else if (_this.scope == 'read') {
              logger.log('short circuit success');
              return resolve(true);              // Short circuit github auth and return true for reads by master org members
            } else {
              fallbackAuth();
            }
          }
        });
      } else {
        fallbackAuth();
      }
    }).catch(function(err) {
      reject(err);
    });
  });
};

// Translate API response from github into an authorization object.
AuthorizeGithub.prototype._handleGithubResponse = function(res, resolve, reject) {
  try {
    var authorized = false;

    if (this.scope == 'read' && res.permissions.pull) {
      authorized = true;
    } else if (this.scope == 'publish' && res.permissions.push) {
      authorized = true;
    }

    resolve(authorized);
  } catch (e) {
    // The GitHub API returned a response
    // in a format we did not understand.
    reject(e);
  }
};

// Load the most recently published package.json for
// the package we are authorizing against, the repository
// url of this package is used for ACL.
AuthorizeGithub.prototype.loadPackageJSON = function() {
  var _this = this;

  return new Promise(function(resolve, reject) {
    request.get(u.resolve(_this.frontDoorHost, _this.packagePath + '?sharedFetchSecret=' + _this.sharedFetchSecret), {
      json: true
    }, function(err, result) {
      if (err) reject(err);
      else if (result.statusCode === 404) {
        resolve(_this.untrustedPackageJson.versions[_this.untrustedPackageJson['dist-tags'].latest]);
      }
      else if (result.statusCode >= 400 || result.statusCode < 200) reject(Error('bad response status = ' + result.statusCode));
      else {
        if (result.body.repository) resolve(result.body);
        else resolve(_this.untrustedPackageJson.versions[_this.untrustedPackageJson['dist-tags'].latest])
      }
    });
  });
};

// parses repository field from package.json
// returns paramters formatted in a way that
// the github api can easily consume.
AuthorizeGithub.prototype.parseGitUrl = function(packageJSON) {
  var _this = this;

  return new Promise(function(resolve, reject) {
    try {
      var url = packageJSON.repository.url;

      if (url.match(/^(git:\/\/|git@)/)) url = parseGitUrl(url, {extraBaseUrls: /[^/]+/.source});

      var parsedUrl = parseUrl.parse(url),
        splitOrgRepo = parsedUrl.path.split('.git')[0].match(/^\/(.*)\/(.*)$/);

      if (!splitOrgRepo) throw Error("does not appear to be a valid git url.");
      resolve({
        org: splitOrgRepo[1],
        repo: splitOrgRepo[2]
      });
    } catch (e) {
      reject(e);
    }
  });
};

AuthorizeGithub.prototype.whoami = function(credentials, cb) {
  var session = new Session({
      githubHost: this.githubHost,
      debug: this.debug
    }),
    token = 'user-' + credentials.headers.authorization.replace('Bearer ', '');

  session.get(token, cb);
};

module.exports = AuthorizeGithub;

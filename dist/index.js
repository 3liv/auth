'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = auth;

var _debounce = require('utilise/debounce');

var _debounce2 = _interopRequireDefault(_debounce);

var _update = require('utilise/update');

var _update2 = _interopRequireDefault(_update);

var _client = require('utilise/client');

var _client2 = _interopRequireDefault(_client);

var _falsy = require('utilise/falsy');

var _falsy2 = _interopRequireDefault(_falsy);

var _parse = require('utilise/parse');

var _parse2 = _interopRequireDefault(_parse);

var _key = require('utilise/key');

var _key2 = _interopRequireDefault(_key);

var _def = require('utilise/def');

var _def2 = _interopRequireDefault(_def);

var _str = require('utilise/str');

var _str2 = _interopRequireDefault(_str);

var _is = require('utilise/is');

var _is2 = _interopRequireDefault(_is);

var _by = require('utilise/by');

var _by2 = _interopRequireDefault(_by);

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

/* istanbul ignore next */
function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// -------------------------------------------
// User Management Middleware
// -------------------------------------------
function auth(_ref) {
  var session = _ref.session;
  var match = _ref.match;
  var mask = _ref.mask;
  var quick = _ref.quick;

  log('creating');

  // whenever there is a change to a session, refresh their resources
  session.store.sessions = ripple('sessions', session.store.sessions, { from: _falsy2.default, to: _falsy2.default }).on('change.refresh', (0, _debounce2.default)(200)(refresh));

  // this function is used to restore a session from a reconnecting client
  (0, _def2.default)(session.store.sessions, 'create', function create(sid) {
    var socket = values(ripple.io.of('/').sockets).filter((0, _by2.default)('sessionID', sid)).pop();
    session.store.sessions[sid] = (0, _str2.default)(session.store.createSession(socket, session));
  });

  // load users and login on register
  ripple('users', [], { from: _falsy2.default, to: _falsy2.default, mysql: { to: filterInvalid } }).on('change', newuser);

  // register a resource for current user
  ripple('user', {}, {
    from: login(match, quick),
    to: limit(mask),
    cache: 'no-store',
    helpers: { whos: whos, register: register, logout: logout }
  });

  ripple('login-message', message);
}

var filterInvalid = function filterInvalid(res, change) {
  return !change.value.invalid;
};

var login = function login(match, quick) {
  return function (_ref2, _ref3) {
    var body = _ref2.body;
    var value = _ref3.value;

    var attempt = (value || body || {}).attempt;

    if (!attempt) return err('no attempt?');
    log('login attempted', (0, _str2.default)(attempt.email).grey);
    var end = resolve(this.sessionID, attempt || {});

    if (!attempt.email || !attempt.password) return end('missing info');

    // find user record
    var row = ripple('users').filter((0, _by2.default)('email', attempt.email)).pop();

    if (row && match && !match(row)) return end('Your account is not approved');

    // quick register if no matching email
    if (!row && attempt.password) return quick ? !register(this, attempt) : end('Incorrect username/password');

    // calc hash
    var saltHash = hash(row.salt),
        apwdHash = hash(attempt.password),
        atmptHash = hash(saltHash + apwdHash);

    // incorrect password
    if (atmptHash !== row.hash) return end('Incorrect username/password');

    // correct password, set session data
    return end({ id: row.id });
  };
};

var resolve = function resolve(sid) {
  var _ref4 = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];

  var _ref4$email = _ref4.email;
  var email = _ref4$email === undefined ? '' : _ref4$email;
  return function (detail) {
    if (_is2.default.str(detail)) detail = { invalid: true, msg: detail };

    set(sid, 'user', detail);(_is2.default.str(detail) ? err : log)(detail.msg || 'logged in', email, sid.grey);
    return false;
  };
};

var set = function set(sid, name, details) {
  var sessions = ripple('sessions');
  if (!sessions[sid]) ripple('sessions').create(sid);
  sessions[sid] = (0, _parse2.default)(sessions[sid]);
  sessions[sid][name] = details;
  (0, _update2.default)(sid, (0, _str2.default)(sessions[sid]))(sessions);
  // ripple.emit('change', ['sessions', { key: sid }])
  log('sessions updated', (0, _str2.default)(details).grey);
};

var newuser = function newuser(_ref5) {
  var value = _ref5.value;

  if (!value.id || !value.sessionID) return;
  resolve(value.sessionID, value)({ id: value.id });
};

// TODO WTF - fix sign..
function register(_ref6, attempt, body) {
  var _ref6$sessionID = _ref6.sessionID;
  var sessionID = _ref6$sessionID === undefined ? '' : _ref6$sessionID;

  log('registering', attempt.email, sessionID.grey);

  var p = promise(),
      pass = attempt.password,
      salt = Math.random().toString(36).substr(2, 5),
      saltHash = hash(salt),
      apwdHash = hash(pass),
      fullHash = hash(saltHash + apwdHash),
      user = extend({
    email: attempt.email,
    salt: salt,
    hash: fullHash,
    sessionID: sessionID
  })(body);

  ripple('users').once('change', wait(function (r) {
    return user.id;
  })(p.resolve)).push(user);

  return p;
}

var logout = function logout(req, res) {
  log('logout', ripple('sessions'));
  delete req.session.user;
  ripple('sessions')[req.sessionID] = (0, _str2.default)(req.session);
  res.status(204).end();
  ripple.stream(req.sessionID)();
};

var refresh = function refresh(_ref7) {
  var key = _ref7.key;
  return ripple.stream(key)();
};

function message() {
  this.innerHTML = owner.str(ripple('user').msg);
}

function whos(socket) {
  var sessionID = (0, _key2.default)('sessionID')(this) || (0, _key2.default)('sessionID')(socket),
      user = [ripple('sessions')[sessionID]].filter(Boolean).map(_parse2.default).map((0, _key2.default)('user')).pop() || {};

  return ripple('users').filter((0, _by2.default)('id', user.id)).pop() || user;
}

var limit = function limit(fields) {
  return function () {
    var user = whos(this),
        val = _is2.default.fn(fields) ? fields(user) : (0, _key2.default)(fields)(user);

    if (user.invalid) val.invalid = user.invalid;
    if (user.msg) val.msg = user.msg;
    return val;
  };
};

var hash = function hash(thing) {
  return _crypto2.default.createHash('md5').update(thing).digest('hex');
};

var log = require('utilise/log')('[auth]'),
    err = require('utilise/err')('[auth]');
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

function _objectDestructuringEmpty(obj) { if (obj == null) throw new TypeError("Cannot destructure undefined"); }

// -------------------------------------------
// User Management Middleware
// -------------------------------------------
function auth(_ref) {
  var session = _ref.session;
  var match = _ref.match;
  var mask = _ref.mask;
  var quick = _ref.quick;

  log('creating');

  // this function is used to restore a session from a reconnecting client
  (0, _def2.default)(session.store.sessions, 'create', function create(sid) {
    var socket = values(ripple.io.of('/').sockets).filter((0, _by2.default)('sessionID', sid)).pop();
    session.store.sessions[sid] = (0, _str2.default)(session.store.createSession(socket, session));
  });

  var loaded = {
    // whenever there is a change to a session, refresh their resources

    sessions: function sessions(ripple, _ref2) {
      var body = _ref2.body;
      body.on('change.refresh', (0, _debounce2.default)(200)(refresh));
    }
    // load users and login on register
    ,
    users: function users(ripple) {
      ripple.connections.mysql.load('users').then(function (rows) {
        return ripple('users', rows.reduce(to.obj, {})).on('change', newUser);
      });
    }
  };

  return [{ name: 'sessions',
    body: session.store.sessions,
    headers: { loaded: loaded.sessions, from: _falsy2.default, to: _falsy2.default }
  }, { name: 'users',
    body: {},
    headers: { loaded: loaded.users, from: register, to: function to(d) {
        return {};
      } }
  }, { name: 'user',
    body: {},
    headers: {
      from: login(match, quick),
      to: limit(mask),
      cache: 'no-store',
      helpers: { whos: whos /*, register, logout*/ }
    }
  }];
}

var login = function login(match, quick) {
  return function (_ref3, _ref4) {
    var body = _ref3.body;
    var value = _ref4.value;

    var _ref5 = value || body || {};

    var attempt = _ref5.attempt;

    if (!attempt) return err('no attempt?'), false;
    log('login attempted', (0, _str2.default)(attempt.email).grey);
    var end = resolve(this.sessionID, attempt || {});

    if (!attempt.email || !attempt.password) return end('Missing username/password');

    // find user record
    var row = values(ripple('users')).filter((0, _by2.default)('email', attempt.email)).pop();

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
  var _ref6 = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];

  var _ref6$email = _ref6.email;
  var email = _ref6$email === undefined ? '' : _ref6$email;
  return function (detail) {
    if (_is2.default.str(detail)) detail = { invalid: true, msg: detail };

    set(sid, 'user', detail);(detail.invalid ? err : log)(detail.msg || 'logged in', email, sid.grey);
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

var newUser = function newUser(_ref7) {
  var value = _ref7.value;

  if (!value.id || !value.sessionID) return;
  console.log("new user");
  resolve(value.sessionID, value)({ id: value.id });
};

// const register = ({ sessionID = '' }, { email, password }, body) => {
function register(_ref8, _ref9, respond) {
  var key = _ref9.key;
  var type = _ref9.type;
  var value = _ref9.value;

  _objectDestructuringEmpty(_ref8);

  if (type !== 'register') return respond(err(400, 'can only register users')), false;

  var sessionID = this.sessionID;
  var email = value.email;
  var password = value.password;
  var users = ripple('users');
  var my = ripple.connections.mysql;
  var salt = Math.random().toString(36).substr(2, 5);
  var saltHash = hash(salt);
  var apwdHash = hash(password);
  var fullHash = hash(saltHash + apwdHash);
  var user = extend({
    email: email,
    salt: salt,
    hash: fullHash,
    sessionID: sessionID
  })(value);

  if (values(users).some((0, _by2.default)('email', email))) return console.log(!respond(err(409, 'user registered', email))), false;

  log('registering', email, sessionID.grey);

  my.add('users', user).then(function (id) {
    return respond(log(200, 'added user'.green, !!(0, _update2.default)(id, (user.id = id, user))(users)));
  });

  return false;
}

// const logout = (req, res) => {
//   log('logout', ripple('sessions'))
//   delete req.session.user
//   ripple('sessions')[req.sessionID] = str(req.session)
//   res.status(204).end()
//   ripple.stream(req.sessionID)()
// }

// const refresh = ({ key }) => ripple.stream(key)()
var refresh = function refresh(_ref10) {
  var key = _ref10.key;

  console.log("refresh", ripple('sessions'));
  ripple.stream(key)();
};

var whos = function whos(socket) {
  var sessionID = (0, _key2.default)('sessionID')(socket),
      user = [ripple('sessions')[sessionID]].filter(Boolean).map(_parse2.default).map((0, _key2.default)('user')).pop() || {};

  return ripple('users')[user.id] || user;
};

var limit = function limit(fields) {
  return function () {
    var user = whos(this),
        val = (0, _key2.default)(fields)(user);

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
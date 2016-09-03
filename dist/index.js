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

var _noop = require('utilise/noop');

var _noop2 = _interopRequireDefault(_noop);

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

var _to = require('utilise/to');

var _to2 = _interopRequireDefault(_to);

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _moment = require('moment');

var _moment2 = _interopRequireDefault(_moment);

/* istanbul ignore next */
function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// -------------------------------------------
// User Management Middleware
// -------------------------------------------
function auth(_ref) {
  var ripple = _ref.ripple;
  var match = _ref.match;
  var mask = _ref.mask;
  var quick = _ref.quick;

  log('creating');

  var loaded = {
    sessions: function sessions(ripple, _ref2) {
      var body = _ref2.body;

      // whenever there is a change to a session, refresh their resources
      body.on('change.refresh', (0, _debounce2.default)(200)(function (_ref3) {
        var key = _ref3.key;

        ripple.send(key.split('.').shift())();
      }));

      ripple.io.on('connection', function (socket) {
        var sessionID = socket.sessionID;

        body[sessionID] = body[sessionID] || {};
        Object.defineProperty(socket, 'user', {
          get: function get(d) {
            return body[sessionID] && body[sessionID].user || {};
          }
        });

        (0, _update2.default)(sessionID + '.' + socket.id, socket)(body);
        socket.on('disconnect', function (d) {
          remove(sessionID + '.' + socket.id)(body);
          if (!keys(body[sessionID]).length) remove(sessionID)(body);
        });
      });
    }

    // load users and login on register
    ,
    users: function users(ripple) {
      my.load('users').then(function (rows) {
        return ripple('users', rows.reduce(_to2.default.obj, {}));
      })
      // .on('change', newUser))
      .catch(err);
    }
  };

  return {
    sessions: {
      name: 'sessions',
      body: {},
      headers: { from: _falsy2.default, to: _falsy2.default, loaded: loaded.sessions }
    },
    users: {
      name: 'users',
      body: {},
      headers: { from: _falsy2.default, to: _falsy2.default, loaded: loaded.users }
    },
    user: {
      name: 'user',
      body: {},
      headers: {
        from: from(match, quick),
        to: limit(mask),
        cache: 'no-store',
        helpers: { whos: whos, isValidPassword: isValidPassword }
      }
    }
  };
}

var from = function from(match, quick) {
  return function (req, res) {
    return req.type == 'register' ? register(req, res) : req.type == 'forgot' ? forgot(req, res) : req.type == 'logout' ? logout(req, res) : req.type == 'reset' ? reset(req, res) : req.type == 'login' ? login(match, quick)(req, res) : (err('no verb', req.type), false);
  };
};

var login = function login(match, quick) {
  return function (req, res) {
    log('login user', (0, _str2.default)(email).grey);

    var _req$value = req.value;
    var value = _req$value === undefined ? {} : _req$value;
    var type = req.type;
    var key = req.key;
    var socket = req.socket;
    var email = value.email;
    var password = value.password;
    var end = setSession(socket.sessionID, email);

    if (!email || !password) return end('Missing username/password');

    // find user record
    var row = values(ripple('users')).filter((0, _by2.default)('email', email)).pop();

    // quick register if no matching email
    if (!row && password) return quick ? register(req, res) : end('Incorrect username/password');

    // calc hash
    var saltHash = hash(row.salt),
        apwdHash = hash(password),
        atmptHash = hash(saltHash + apwdHash);

    // incorrect password
    if (atmptHash !== row.hash) return end('Incorrect username/password');

    if (row && match && (match = match(row))) return end(match);

    // correct password, set session data
    return end(row);
  };
};

var setSession = function setSession(sessionID) {
  var email = arguments.length <= 1 || arguments[1] === undefined ? '' : arguments[1];
  return function (detail) {
    var sessions = ripple('sessions'),
        user = _is2.default.str(detail) ? { invalid: true, msg: detail } : detail,
        fn = user.invalid ? err : log;

    fn(user.msg || 'logged in'.green, email.bold, sessionID.grey);
    (0, _update2.default)(sessionID + '.user', user)(sessions);
  };
};

var newUser = function newUser(_ref4) {
  var value = _ref4.value;
  var id = value.id;
  var email = value.email;
  var sessionID = value.sessionID;

  if (!id || !sessionID) return;
  setSession(sessionID, email)(ripple('users')[id]);
};

var register = function register(_ref5, res) {
  var value = _ref5.value;
  var _ref5$socket = _ref5.socket;
  var socket = _ref5$socket === undefined ? {} : _ref5$socket;
  var _socket$sessionID = socket.sessionID;
  var sessionID = _socket$sessionID === undefined ? '' : _socket$sessionID;
  var email = value.email;
  var _value$password = value.password;
  var password = _value$password === undefined ? randompass() : _value$password;
  var users = ripple('users');

  var _ripple = ripple('templates');

  var template = _ripple.template;
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
  var to = email;
  var text = template && template('join', { email: email, password: password });
  var subject = "Welcome " + value.firstname;

  if (values(users).some((0, _by2.default)('email', email))) return res(400, err('There is already a user registered with that email', email)), false;

  log('registering', email, sessionID.grey);

  my.add('users', user).then(function (id) {
    return mailer && mailer({ to: to, subject: subject, text: text }), id;
  }).then(function (id) {
    return (0, _update2.default)(id, (user.id = id, user))(users), id;
  }).then(function (id) {
    return log('added user'.green, id);
  }).then(function (id) {
    return res(200, 'User added');
  }).catch(err);
};

var logout = function logout(_ref6, res) {
  var socket = _ref6.socket;
  var sessionID = socket.sessionID;

  log('logout'.green, 'user'.bold, sessionID.grey);
  remove(sessionID + '.user')(ripple('sessions'));
};

var forgot = function forgot(_ref7, res) {
  var value = _ref7.value;
  var email = value.email;
  var forgot_code = randomise();
  var forgot_time = new Date();
  var users = ripple('users');

  var _ripple2 = ripple('templates');

  var template = _ripple2.template;
  var me = values(users).filter((0, _by2.default)('email', email)).pop();
  var subject = "Forgot Password";
  var text = template('forgot', { forgot_code: forgot_code });
  var to = me && me.email;
  var id = me && me.id;

  if (!me) return time(2000, function (d) {
    return res(200, err('forgot invalid email', email));
  }), false;

  my.update('users', { id: id, forgot_code: forgot_code, forgot_time: forgot_time }).then(function (id) {
    (0, _update2.default)(id + '.forgot_code', forgot_code)(users);
    (0, _update2.default)(id + '.forgot_time', new Date())(users);
  }).then(function (d) {
    return mailer && mailer({ to: to, subject: subject, text: text });
  }).then(function (d) {
    return res(log(200, 'forgot password'.green, email.green));
  }).catch(err);
};

var reset = function reset(_ref8, res) {
  var value = _ref8.value;
  var code = value.code;
  var password = value.password;

  var _ripple3 = ripple('user');

  var isValidPassword = _ripple3.isValidPassword;
  var users = ripple('users');
  var me = values(users).filter((0, _by2.default)('forgot_code', code)).filter((0, _by2.default)('forgot_time', function (d) {
    return (0, _moment2.default)().subtract(24, 'hours') < d < (0, _moment2.default)();
  })).pop();

  if (!me) return res(403, err('reset code invalid', code)), false;
  if (!isValidPassword(password)) return res(403, err('reset password invalid', code)), false;

  var id = me.id;
  var salt = Math.random().toString(36).substr(2, 5);
  var saltHash = hash(salt);
  var apwdHash = hash(password);
  var fullHash = hash(saltHash + apwdHash);
  var forgot_code = '';
  var forgot_time = '';

  my.update('users', { id: id, forgot_code: forgot_code, forgot_time: forgot_time, salt: salt, hash: fullHash }).then(function (id) {
    (0, _update2.default)(id + '.salt', salt)(users);
    (0, _update2.default)(id + '.hash', fullHash)(users);
    (0, _update2.default)(id + '.forgot_code', forgot_code)(users);
    (0, _update2.default)(id + '.forgot_time', forgot_time)(users);
    res(200, log('reset password'.green, (0, _str2.default)(id).grey));
  }).catch(err);
};

var randomise = function randomise(d) {
  return Math.random().toString(36).substr(2, 5) + Math.random().toString(36).substr(2, 5) + Math.random().toString(36).substr(2, 5);
};

var whos = function whos(_ref9) {
  var sessionID = _ref9.sessionID;
  return ripple('sessions')[sessionID] && ripple('sessions')[sessionID].user || {};
};

var limit = function limit(fields) {
  return function (req) {
    var user = whos(req.socket);
    req.value = (0, _key2.default)(fields)(user);

    if (user.invalid) req.value.invalid = user.invalid;
    if (user.msg) req.value.msg = user.msg;
    return req;
  };
};

var hash = function hash(thing) {
  return _crypto2.default.createHash('md5').update(thing).digest('hex');
};

var isValidPassword = function isValidPassword(d) {
  return (/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/.test(d)
  );
};

var randompass = function randompass(d) {
  return Math.random().toString(36).slice(-8);
};

var log = require('utilise/log')('[auth]'),
    err = require('utilise/err')('[auth]');
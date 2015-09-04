"use strict";

/* istanbul ignore next */
var _interopRequire = function (obj) { return obj && obj.__esModule ? obj["default"] : obj; };

// -------------------------------------------
// User Management Middleware
// -------------------------------------------
module.exports = auth;

function auth() {
  var opts = arguments[0] === undefined ? {} : arguments[0];

  var session = opts.session,
      match = opts.login,
      mask = opts.mask,
      body = session.store.sessions,
      quick = opts.quick,
      headers = { from: falsy, to: falsy };

  // this function is used to restore a session from a reconnecting client
  def(body, "create", function create(sid) {
    var socket = ripple.io.of("/").sockets.filter(by("sessionID", sid)).pop();
    body[sid] = str(session.store.createSession(socket, session));
  });

  // load users and login on register
  ripple("users", [], { from: falsy, to: falsy }).on("change", newuser);

  // whenever there is a change to session, refresh their resources
  ripple("sessions", body, headers).on("change", debounce(200)(refresh));

  // register a resource for current user
  ripple("user", { whos: whos, register: register, logout: logout }, { from: login(match, quick), to: limit(mask), cache: null });

  ripple("auth-check", check);
}

function login(match, quick) {
  return function (attempt) {
    if (!attempt) return err("no attempt?");

    var end = resolve(this.sessionID, attempt || {});

    if (!attempt.username || !attempt.password) return end("missing info");

    // find user record
    var row = ripple("users").filter(match(attempt) || by("username", attempt.username)).pop();

    // quick register if no matching username
    if (!row && attempt.password) return quick ? register(this, attempt) : end("incorrect username");

    // calc hash
    var saltHash = crypto.createHash("md5").update(row.salt).digest("hex"),
        apwdHash = crypto.createHash("md5").update(attempt.password).digest("hex"),
        atmptHash = crypto.createHash("md5").update(saltHash + apwdHash).digest("hex");

    // incorrect password
    if (atmptHash !== row.hash) return end("incorrect password");

    // correct password, set session data
    return end({ id: row.id });
  };
}

function resolve(sid) {
  var _ref = arguments[1] === undefined ? {} : arguments[1];

  var _ref$username = _ref.username;
  var username = _ref$username === undefined ? "" : _ref$username;

  return function (detail) {
    var say = is.str(detail) ? err : log;
    is.str(detail) && (detail = { invalid: true, msg: detail });
    set(sid, "user", detail);
    say(detail.msg || "logged in", username, sid.grey);
    return false;
  };
}

function set(sid, name, details) {
  var sessions = ripple("sessions");
  if (!sessions[sid]) ripple("sessions").create(sid);
  sessions[sid] = parse(sessions[sid]);
  sessions[sid][name] = details;
  sessions[sid] = str(sessions[sid]);
}

function newuser(users, _ref) {
  var _ref$value = _ref.value;
  var value = _ref$value === undefined ? {} : _ref$value;

  if (!value.id || !value.sessionID) {
    return;
  }resolve(value.sessionID, value)({ id: value.id });
}

function register(_ref, attempt, body) {
  var _ref$sessionID = _ref.sessionID;
  var sessionID = _ref$sessionID === undefined ? "" : _ref$sessionID;

  log("registering", attempt.username, sessionID.grey);

  var p = promise(),
      pass = attempt.password,
      salt = Math.random().toString(36).substr(2, 5),
      saltHash = crypto.createHash("md5").update(salt).digest("hex"),
      apwdHash = crypto.createHash("md5").update(pass).digest("hex"),
      fullHash = crypto.createHash("md5").update(saltHash + apwdHash).digest("hex"),
      user = extend({
    username: attempt.username,
    salt: salt,
    hash: fullHash,
    sessionID: sessionID
  })(body);

  ripple("users").once("change", wait(function (r) {
    return user.id;
  })(p.resolve)).push(user);

  return p;
}

function logout(req, res) {
  log("logout", ripple("sessions"));
  delete req.session.user;
  ripple("sessions")[req.sessionID] = str(req.session);
  res.status(204).end();
  ripple.sync(req.sessionID)();
}

function refresh(d, change) {
  ripple.sync(change.key)();
}

function check(req, res, next) {
  if (client && !window.ripple) {
    return;
  }var me = client ? ripple("user") : whos(req),
      from = client ? location.pathname : req.url,
      open = is["in"](["/invalid", "/login", "/not-approved"])(from),
      to = me.invalid ? "/invalid" : !me.username ? "/login" : !me.approved ? "/not-approved" : open ? "/dashboard" : from;

  if (!from) {
    return log("auth-check", me.username, from, to);
  }from != to && log("auth-check redirecting", from, to);

  return client && from !== to ? request(to)() : !client && from !== to ? res.redirect(to) : !client ? next() : undefined;
}

function whos(socket) {
  var sessionID = key("sessionID")(this) || key("sessionID")(socket),
      user = [ripple("sessions")[sessionID]].filter(Boolean).map(parse).map(key("user")).pop() || {};

  return ripple("users").filter(by("id", user.id)).pop() || user;
}

function limit(fields) {
  return function () {
    var user = whos(this),
        val = is.fn(fields) ? fields(user) : key(fields)(user);

    user.invalid && (val.invalid = user.invalid);
    user.msg && (val.msg = user.msg);

    return val;
  };
}

var debounce = _interopRequire(require("utilise/debounce"));

var client = _interopRequire(require("utilise/client"));

var falsy = _interopRequire(require("utilise/falsy"));

var parse = _interopRequire(require("utilise/parse"));

var key = _interopRequire(require("utilise/key"));

var def = _interopRequire(require("utilise/def"));

var log = _interopRequire(require("utilise/log"));

var err = _interopRequire(require("utilise/err"));

var str = _interopRequire(require("utilise/str"));

var is = _interopRequire(require("utilise/is"));

var by = _interopRequire(require("utilise/by"));

var crypto = _interopRequire(require("crypto"));

log = log("[auth]");
err = err("[auth]");
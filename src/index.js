// -------------------------------------------
// User Management Middleware
// -------------------------------------------
export default function auth(opts = {}){
  var session = opts.session
    , match = opts.login
    , mask = opts.mask
    , body = session.store.sessions
    , quick = opts.quick
    , headers = { from: falsy, to: falsy }

  // this function is used to restore a session from a reconnecting client
  def(body, 'create', function create(sid){
    var socket = ripple.io.of("/").sockets.filter(by('sessionID', sid)).pop()
    body[sid] = str(session.store.createSession(socket, session))
  })

  // load users and login on register
  ripple('users', [], { from: falsy, to: falsy })
    .on('change', newuser)

  // whenever there is a change to session, refresh their resources
  ripple('sessions', body, headers)
    .on('change', debounce(200)(refresh))

  // register a resource for current user
  ripple('user', { whos, register, logout }, { from: login(match, quick), to: limit(mask), cache: null })

  ripple('auth-check', opts.check || check)

  ripple('login-message', message)
}

function login(match, quick){
  return function(attempt){ 
    if (!attempt) return err('no attempt?') 

    var end = resolve(this.sessionID, attempt || {})

    if (!attempt.email || !attempt.password) return end('missing info')

    // find user record
    var row = ripple('users')
      .filter(by('email', attempt.email))
      .pop()

    if (row && match && !match(row)) return end('Your account is not approved')

    // quick register if no matching email
    if (!row && attempt.password) return quick ? register(this, attempt) : end('Incorrect username/password')

    // calc hash
    var saltHash = hash(row.salt)
      , apwdHash = hash(attempt.password)
      , atmptHash = hash(saltHash + apwdHash)

    // incorrect password
    if (atmptHash !== row.hash) return end('Incorrect username/password')

    // correct password, set session data
    return end({ id: row.id })
  }
}

function resolve(sid, { email = '' } = {}){
  return function(detail){
    var say = is.str(detail) ? err : log
    is.str(detail) && (detail = { invalid: true, msg: detail })
    set(sid, 'user', detail)
    say(detail.msg || 'logged in', email, sid.grey)
    return false
  }
}

function set(sid, name, details) {
  var sessions = ripple('sessions')
  if (!sessions[sid]) ripple('sessions').create(sid)
  sessions[sid] = parse(sessions[sid])
  sessions[sid][name] = details
  sessions[sid] = str(sessions[sid])
}

function newuser(users, { value = {}} ){
  if (!value.id || !value.sessionID) return
  resolve(value.sessionID, value)({ id: value.id })
}

function register({ sessionID = '' }, attempt, body) {
  log('registering', attempt.email, sessionID.grey)
  
  var p = promise()
    , pass = attempt.password
    , salt = Math.random().toString(36).substr(2, 5)
    , saltHash = hash(salt)
    , apwdHash = hash(pass)
    , fullHash = hash(saltHash + apwdHash)
    , user = extend({ 
        email: attempt.email
      , salt: salt
      , hash: fullHash
      , sessionID: sessionID
      })(body)

  ripple('users')
    .once('change', wait(r => user.id)(p.resolve))
    .push(user)

  return p
}

function logout(req, res) {
  log('logout', ripple('sessions'))
  delete req.session.user
  ripple('sessions')[req.sessionID] = str(req.session)
  res.status(204).end()
  ripple.sync(req.sessionID)() 
}

function refresh(d, change) {
  ripple.sync(change.key)()
}

function message(){
  this.innerHTML = str(ripple('user').msg)
}

function check(req, res, next){
  if (client && !window.ripple) return;

  var me = client ? ripple('user') : whos(req)
    , from = client ? location.pathname : req.url
    , open = is.in(['/invalid', '/login', '/not-approved'])(from)
    , to =  me.invalid  ? '/invalid'
         : !me.email    ? '/login'
         : !me.approved ? '/not-approved'
         :  open        ? '/dashboard'
                        : from

  if (!from) return log('auth-check', me.email, from, to);

  from != to && log('auth-check redirecting', from, to)

  return  client && from !== to ? request(to)() 
       : !client && from !== to ? res.redirect(to)
       : !client                ? next()
       : undefined
}

function whos(socket){ 
  var sessionID = key('sessionID')(this) || key('sessionID')(socket)
    , user = [ripple('sessions')[sessionID]]
        .filter(Boolean)
        .map(parse)
        .map(key('user'))
        .pop() || {}

  return ripple('users')
    .filter(by('id', user.id))
    .pop() || user
}

function limit(fields){
  return function(){
    var user = whos(this)
      , val = is.fn(fields) 
            ? fields(user)
            : key(fields)(user)

    user.invalid && (val.invalid = user.invalid)
    user.msg && (val.msg = user.msg)
    
    return val
  }
}

function hash(thing){
  return crypto
    .createHash('md5')
    .update(thing)
    .digest('hex')
}

import debounce from 'utilise/debounce'
import client from 'utilise/client'
import falsy from 'utilise/falsy'
import parse from 'utilise/parse'
import key from 'utilise/key'
import def from 'utilise/def'
import log from 'utilise/log'
import err from 'utilise/err'
import str from 'utilise/str'
import is from 'utilise/is'
import by from 'utilise/by'
import crypto from 'crypto'
log = log('[auth]')
err = err('[auth]')


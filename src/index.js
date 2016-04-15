// -------------------------------------------
// User Management Middleware
// -------------------------------------------
export default function auth({ session, match, mask, quick }){
  log('creating')
  
  // whenever there is a change to a session, refresh their resources
  session.store.sessions = ripple('sessions', session.store.sessions, { from: falsy, to: falsy })
    .on('change.refresh', debounce(200)(refresh))

  // this function is used to restore a session from a reconnecting client
  def(session.store.sessions, 'create', function create(sid){
    var socket = values(ripple.io.of('/').sockets).filter(by('sessionID', sid)).pop()
    session.store.sessions[sid] = str(session.store.createSession(socket, session))
  })

  // load users and login on register
  ripple('users', [], { from: falsy, to: falsy, mysql: { to: filterInvalid } })
    .on('change', newuser)

  // register a resource for current user
  ripple('user', {}, { 
    from: login(match, quick)
  , to: limit(mask)
  , cache: 'no-store' 
  , helpers: { whos, register, logout }
  })

  ripple('login-message', message)
}

const filterInvalid = (res, change) => !change.value.invalid

const login = (match, quick) => function({ body }, { value }){ 
  const attempt = (value || body || {}).attempt
  
  if (!attempt) return err('no attempt?') 
  log('login attempted', str(attempt.email).grey)
  const end = resolve(this.sessionID, attempt || {})

  if (!attempt.email || !attempt.password) 
    return end('missing info')

  // find user record
  const row = ripple('users')
    .filter(by('email', attempt.email))
    .pop()

  if (row && match && !match(row)) 
    return end('Your account is not approved')

  // quick register if no matching email
  if (!row && attempt.password) 
    return quick ? !register(this, attempt) : end('Incorrect username/password')

  // calc hash
  const saltHash = hash(row.salt)
      , apwdHash = hash(attempt.password)
      , atmptHash = hash(saltHash + apwdHash)

  // incorrect password
  if (atmptHash !== row.hash) 
    return end('Incorrect username/password')

  // correct password, set session data
  return end({ id: row.id })
}

const resolve = (sid, { email = '' } = {}) => detail => {
  if (is.str(detail)) 
    detail = { invalid: true, msg: detail }

  set(sid, 'user', detail)

  ;(is.str(detail) ? err : log)(detail.msg || 'logged in', email, sid.grey)
  return false
}

const set = (sid, name, details) => {
  var sessions = ripple('sessions')
  if (!sessions[sid]) ripple('sessions').create(sid)
  sessions[sid] = parse(sessions[sid])
  sessions[sid][name] = details
  update(sid, str(sessions[sid]))(sessions)
  // ripple.emit('change', ['sessions', { key: sid }])
  log('sessions updated', str(details).grey)
}

const newuser = ({ value }) => {
  if (!value.id || !value.sessionID) return
  resolve(value.sessionID, value)({ id: value.id })
}

// TODO WTF - fix sign..
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

const logout = (req, res) => {
  log('logout', ripple('sessions'))
  delete req.session.user
  ripple('sessions')[req.sessionID] = str(req.session)
  res.status(204).end()
  ripple.stream(req.sessionID)() 
}

const refresh = ({ key }) => ripple.stream(key)()

function message(){
  this.innerHTML = owner.str(ripple('user').msg)
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

const limit = fields => function(){
  const user = whos(this)
      , val = is.fn(fields) ? fields(user) : key(fields)(user)

  if (user.invalid) val.invalid = user.invalid
  if (user.msg) val.msg = user.msg
  return val
}

const hash = thing => crypto
  .createHash('md5')
  .update(thing)
  .digest('hex')

import debounce from 'utilise/debounce'
import update from 'utilise/update'
import client from 'utilise/client'
import falsy from 'utilise/falsy'
import parse from 'utilise/parse'
import key from 'utilise/key'
import def from 'utilise/def'
import str from 'utilise/str'
import is from 'utilise/is'
import by from 'utilise/by'
import crypto from 'crypto'
var log = require('utilise/log')('[auth]')
  , err = require('utilise/err')('[auth]')


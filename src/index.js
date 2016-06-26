// -------------------------------------------
// User Management Middleware
// -------------------------------------------
export default function auth({ session, match, mask, quick }){
  log('creating')

  // this function is used to restore a session from a reconnecting client
  def(session.store.sessions, 'create', function create(sid){
    var socket = values(ripple.io.of('/').sockets).filter(by('sessionID', sid)).pop()
    session.store.sessions[sid] = str(session.store.createSession(socket, session))
  })
  
  const loaded = {
          // whenever there is a change to a session, refresh their resources
          sessions(ripple, { body }) { body.on('change.refresh', debounce(200)(refresh)) }
          // load users and login on register
        , users(ripple) { ripple.connections.mysql.load('users')
            .then(rows => 
              ripple('users', rows
                .reduce(to.obj, {}))
              .on('change', newUser))
          }
        }

  return [
    { name: 'sessions'
    , body: session.store.sessions
    , headers: { loaded: loaded.sessions, from: falsy, to: falsy }
    }
  , { name: 'users'
    , body: {}
    , headers: { loaded: loaded.users, from: register, to: d => ({}) }
    }
  , { name: 'user'
    , body: {}
    , headers: { 
        from: login(match, quick)
      , to: limit(mask)
      , cache: 'no-store' 
      , helpers: { whos/*, register, logout*/ }
      } 
    }
  ]
}

const login = (match, quick) => function({ body }, { value }){ 
  const { attempt } = value || body || {}
  
  if (!attempt) return err('no attempt?'), false
  log('login attempted', str(attempt.email).grey)
  const end = resolve(this.sessionID, attempt || {})

  if (!attempt.email || !attempt.password) 
    return end('Missing username/password')

  // find user record
  const row = values(ripple('users'))
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

  ;(detail.invalid ? err : log)(detail.msg || 'logged in', email, sid.grey)
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

const newUser = ({ value }) => {
  if (!value.id || !value.sessionID) return
  console.log("new user")
  resolve(value.sessionID, value)({ id: value.id })
}

// const register = ({ sessionID = '' }, { email, password }, body) => {
function register({}, { key, type, value }, respond) {
  if (type !== 'register') return respond(err(400, 'can only register users')), false
  
  const { sessionID } = this
      , { email, password } = value
      , users = ripple('users')
      , my = ripple.connections.mysql
      , salt = Math.random().toString(36).substr(2, 5)
      , saltHash = hash(salt)
      , apwdHash = hash(password)
      , fullHash = hash(saltHash + apwdHash)
      , user = extend({ 
          email
        , salt
        , hash: fullHash
        , sessionID
        })(value)

  if (values(users).some(by('email', email))) 
    return respond(err(409, 'user registered', email)), false

  log('registering', email, sessionID.grey)

  my.add('users', user)
    .then(id => respond(log(200, 'added user'.green, !!update(id, (user.id = id, user))(users))))

  return false
}

// const logout = (req, res) => {
//   log('logout', ripple('sessions'))
//   delete req.session.user
//   ripple('sessions')[req.sessionID] = str(req.session)
//   res.status(204).end()
//   ripple.stream(req.sessionID)() 
// }

// const refresh = ({ key }) => ripple.stream(key)()
const refresh = function({ key }){
  console.log("refresh", ripple('sessions'))
  ripple.stream(key)()
}

const whos = (socket) => { 
  const sessionID = key('sessionID')(socket)
      , user = [ripple('sessions')[sessionID]]
          .filter(Boolean)
          .map(parse)
          .map(key('user'))
          .pop() || {}

  return ripple('users')[user.id] || user
}

const limit = fields => function(){
  const user = whos(this)
      , val  = key(fields)(user)

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


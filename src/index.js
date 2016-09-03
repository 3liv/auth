// -------------------------------------------
// User Management Middleware
// -------------------------------------------
export default function auth({ ripple, match, mask, quick }){
  log('creating')

  const loaded = {
    sessions(ripple, { body }) { 
      // whenever there is a change to a session, refresh their resources
      body.on('change.refresh', debounce(200)(({ key }) => {
        ripple.send(key.split('.').shift())()
      }))

      ripple.io.on('connection', socket => {
        const { sessionID } = socket
        body[sessionID] = body[sessionID] || {}
        Object.defineProperty(socket, 'user', { 
          get: d => body[sessionID] && body[sessionID].user || {}
        })

        update(`${sessionID}.${socket.id}`, socket)(body)
        socket.on('disconnect', d => {
          remove(`${sessionID}.${socket.id}`)(body)
          if (!keys(body[sessionID]).length)
            remove(sessionID)(body)
        })
      })
    }
    
    // load users and login on register
  , users(ripple) { my.load('users')
      .then(rows => ripple('users', rows.reduce(to.obj, {})))
          // .on('change', newUser))
      .catch(err)
    }
  }

  return {
    sessions: { 
      name: 'sessions'
    , body: {}
    , headers: { from: falsy, to: falsy, loaded: loaded.sessions }
    }
  , users: { 
      name: 'users'
    , body: {}
    , headers: { from: falsy, to: falsy, loaded: loaded.users }
    }
  , user: { 
      name: 'user'
    , body: {}
    , headers: { 
        from: from(match, quick)
      , to: limit(mask)
      , cache: 'no-store' 
      , helpers: { whos, isValidPassword }
      } 
    }
  }
}

const from = (match, quick) => (req, res) => 
  req.type == 'register' ? register(req, res)
: req.type == 'forgot'   ? forgot(req, res)
: req.type == 'logout'   ? logout(req, res)
: req.type == 'reset'    ? reset(req, res)
: req.type == 'login'    ? login(match, quick)(req, res)
: (err('no verb', req.type), false)

const login = (match, quick) => (req, res) => { 
  log('login user', str(email).grey)

  const { value = {}, type, key, socket } = req
      , { email, password } = value
      , end = setSession(socket.sessionID, email)

  if (!email || !password) 
    return end('Missing username/password')

  // find user record
  const row = values(ripple('users'))
    .filter(by('email', email))
    .pop()

  // quick register if no matching email
  if (!row && password) 
    return quick ? register(req, res) : end('Incorrect username/password')

  // calc hash
  const saltHash = hash(row.salt)
      , apwdHash = hash(password)
      , atmptHash = hash(saltHash + apwdHash)

  // incorrect password
  if (atmptHash !== row.hash) 
    return end('Incorrect username/password')

  if (row && match && (match = match(row))) 
    return end(match)

  // correct password, set session data
  return end(row)
}

const setSession = (sessionID, email = '') => detail => {
  const sessions = ripple('sessions')
      , user = is.str(detail) ? { invalid: true, msg: detail } : detail
      , fn = user.invalid ? err : log

  fn(user.msg || 'logged in'.green, email.bold, sessionID.grey)
  update(`${sessionID}.user`, user)(sessions)
}

const newUser = ({ value }) => {
  const { id, email, sessionID } = value
  if (!id || !sessionID) return
  setSession(sessionID, email)(ripple('users')[id])
}

const register = ({ value, socket }, res) => {
  const { sessionID } = socket
      , { email, password } = value
      , users = ripple('users')
      , { template } = ripple('templates')
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
      , to = email
      , text = template && template('join', { email, password })
      , subject = "Welcome " + value.firstname

  if (values(users).some(by('email', email))) 
    return res(err(409, 'user registered', email)), false

  log('registering', email, sessionID.grey)
 
  my.add('users', user)
    .then(id => (mailer && mailer({ to, subject, text }), id))
    .then(id => res(log(200, 'added user'.green, !!update(id, (user.id = id, user))(users))))
    .catch(err)
}

const logout = ({ socket }, res) => {
  const { sessionID } = socket
  log('logout'.green, 'user'.bold, sessionID.grey)
  remove(`${sessionID}.user`)(ripple('sessions'))
}

const forgot = ({ value }, res) => {
  const { email } = value
      , forgot_code = randomise()
      , forgot_time = new Date()
      , users = ripple('users')
      , { template } = ripple('templates')
      , my = ripple.connections.mysql
      , me = values(users)
          .filter(by('email', email))
          .pop()
      , subject = "Forgot Password"
      , text = template('forgot', { forgot_code })
      , to = me && me.email
      , id = me && me.id

  if (!me) return time(2000, d => res(200, err('forgot invalid email', email))), false

  my.update('users', { id, forgot_code, forgot_time })
    .then(id => {
      update(`${id}.forgot_code`, forgot_code)(users)
      update(`${id}.forgot_time`, new Date())(users)
    })
    .then(d => mailer && mailer({ to, subject, text }))
    .then(d => res(log(200, 'forgot password'.green, email.green)))
    .catch(err)
}

const reset = ({ value }, res) => {
  const { code, password } = value
      , { isValidPassword } = ripple('user')
      , users = ripple('users')
      , my = ripple.connections.mysql
      , me = values(users)
          .filter(by('forgot_code', code))
          .filter(by('forgot_time', d => moment().subtract(24, 'hours') < d < moment()))
          .pop()

  if (!me) return res(403, err('reset code invalid', code)), false
  if (!isValidPassword(password)) return res(403, err('reset password invalid', code)), false

  const { id } = me
      , salt = Math.random().toString(36).substr(2, 5)
      , saltHash = hash(salt)
      , apwdHash = hash(password)
      , fullHash = hash(saltHash + apwdHash)
      , forgot_code = ''
      , forgot_time = ''

  my.update('users', { id, forgot_code, forgot_time, salt, hash: fullHash })
    .then(id => {
      update(`${id}.salt`, salt)(users)
      update(`${id}.hash`, fullHash)(users)
      update(`${id}.forgot_code`, forgot_code)(users)
      update(`${id}.forgot_time`, forgot_time)(users)
      res(200, log('reset password'.green, str(id).grey))
    })
    .catch(err)
}

const randomise = d => 
    Math.random().toString(36).substr(2, 5)
  + Math.random().toString(36).substr(2, 5)
  + Math.random().toString(36).substr(2, 5)

const whos = ({ sessionID }) => ripple('sessions')[sessionID] && ripple('sessions')[sessionID].user || {}

const limit = fields => req => {
  const user = whos(req.socket)
  req.value = key(fields)(user)

  if (user.invalid) req.value.invalid = user.invalid
  if (user.msg) req.value.msg = user.msg
  return req
}

const hash = thing => crypto
  .createHash('md5')
  .update(thing)
  .digest('hex')

const isValidPassword = d => /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/.test(d)

import debounce from 'utilise/debounce'
import update from 'utilise/update'
import client from 'utilise/client'
import falsy from 'utilise/falsy'
import parse from 'utilise/parse'
import noop from 'utilise/noop'
import key from 'utilise/key'
import def from 'utilise/def'
import str from 'utilise/str'
import is from 'utilise/is'
import by from 'utilise/by'
import to from 'utilise/to'
import crypto from 'crypto'
import moment from 'moment'
const log = require('utilise/log')('[auth]')
    , err = require('utilise/err')('[auth]')


# Ripple | Sessions
[![Coverage Status](https://coveralls.io/repos/rijs/sessions/badge.svg?branch=master&service=github)](https://coveralls.io/github/rijs/sessions?branch=master)
[![Build Status](https://travis-ci.org/rijs/sessions.svg)](https://travis-ci.org/rijs/sessions)

Adds a uniquely identifying `sessionID` to each socket.

It does this by sharing express session data with socket.io. You will need to provide the following options: 

* `secret` — [secret used to sign session ID cookie](https://github.com/expressjs/session#secret)
* `name` — [name of the session ID cookie](https://github.com/expressjs/session#name)

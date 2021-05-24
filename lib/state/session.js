/**
 *
 */

const { getSafeUserSessionID } = require('../utils')

/**
 * Creates an instance of `SessionStore`.
 *
 * This is the state store implementation for the OAuth2Strategy used when
 * the `state` option is enabled.  It generates a random state and stores it in
 * `req.session` and verifies it when the service provider redirects the user
 * back to the application.
 *
 * This state store requires session support.  If no session exists, an error
 * will be thrown.
 *
 * Options:
 *
 *   - `key`  The key in the session under which to store the state
 *
 * @constructor
 * @param {Object} options
 * @api public
 */
function SessionStore(options) {
  if (!options.key) {
    throw new TypeError('Session-based state store requires a session key')
  }

  this._key = options.key
}

/**
 * Store request state.
 *
 * This implementation simply generates a random string and stores the value in
 * the session, where it will be used for verification when the user is
 * redirected back to the application.
 *
 * @param {Object} req
 * @param {Function} callback
 * @api protected
 */
SessionStore.prototype.store = function (req, callback) {
  if (!req.session) {
    callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?'))
    return
  }

  const key = this._key
  const state = getSafeUserSessionID(24)
  if (!req.session[key]) {
    req.session[key] = {}
  }

  req.session[key].state = state
  callback(null, state)
}

/**
 * Verify request state.
 *
 * This implementation simply compares the state parameter in the request to the
 * value generated earlier and stored in the session.
 *
 * @param {Object} req
 * @param {String} providedState
 * @param {Function} callback
 * @api protected
 */
SessionStore.prototype.verify = function (req, providedState, callback) {
  if (!req.session) {
    callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?'))
    return
  }

  const key = this._key
  if (!req.session[key]) {
    callback(null, false, { message: 'Unable to verify authorization request state.' })
    return
  }

  const state = req.session[key].state
  if (!state) {
    callback(null, false, { message: 'Unable to verify authorization request state.' })
    return
  }

  delete req.session[key].state
  if (Object.keys(req.session[key]).length === 0) {
    delete req.session[key]
  }

  if (state !== providedState) {
    callback(null, false, { message: 'Invalid authorization request state.' })
    return
  }

  callback(null, true)
}

// Expose constructor.
module.exports = SessionStore

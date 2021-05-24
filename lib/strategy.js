/**
 * Cas
 */
const http = require('http')
const https = require('https')
const url = require('url')
const util = require('util')

const debug = require('debug')
const parseXML = require('xml2js').parseString
const XMLProcessors = require('xml2js/lib/processors')
const passport = require('passport-strategy')
const { v4: uuid } = require('uuid')

const XML_PROCESSORS_CONFIG = {
  trim: true,
  normalize: true,
  explicitArray: false,
  tagNameProcessors: [XMLProcessors.normalize, XMLProcessors.stripPrefix]
}

const Cas3TicketValidator = (self, req, body, callback) => {
  parseXML(body, XML_PROCESSORS_CONFIG, (err, result) => {
    if (err) {
      callback(new Error('The response from the server was bad'))
      return
    }

    try {
      if (result.serviceresponse.authenticationfailure) {
        callback(new Error(`Authentication failed ${result.serviceresponse.authenticationfailure.$.code}`))
        return
      }

      const success = result.serviceresponse.authenticationsuccess
      if (success) {
        if (self._passReqToCallback) {
          self._verify(req, success, callback)
        } else {
          self._verify(success, callback)
        }
        return
      }
      callback(new Error('Authentication failed'))
    } catch (e) {
      callback(new Error('Authentication result processing FAILED'))
    }
  })
}

/**
 * Creates an instance of `CAS3Strategy`.
 *
 * The CAS3 authentication strategy authenticates requests using a CAS 3.0 host.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new OAuth2Strategy({
 *         authorizationURL: 'https://www.example.com/oauth2/authorize',
 *         tokenURL: 'https://www.example.com/oauth2/token',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function CAS3Strategy (options, verify) {
  if (typeof options === 'function') {
    verify = options
    options = undefined
  }

  options = options || {}

  if (!verify) {
    throw new TypeError('CAS3 authentication strategy requires a verify callback')
  }

  if (!options.casServerURL) {
    throw new TypeError('CAS3 authentication strategy requires `casServerURL` parameter')
  }

  // if (!options.returnTo) {
  //   throw new TypeError('CAS3 authentication strategy requires `returnTo` parameter')
  // }

  // if (!options.service) {
  //   throw new TypeError('CAS3 authentication strategy requires `service` parameter')
  // }

  this.casServerURL = options.casServerURL
  this.serverBaseURL = options.serverBaseURL
  this.validateURL = options.validateURL
  this.serviceURL = options.serviceURL
  this.parsed = new URL(this.casServerURL)
  this.client = this.parsed.protocol === 'http:' ? http : https
  this.name = 'cas3'

  this._verify = verify
  this._passReqToCallback = options.passReqToCallback
  this._validateUri = 'p3/serviceValidate'
  this._validate = Cas3TicketValidator

  passport.Strategy.call(this)
}

/**
 *
 * @param {*} req
 * @param {*} options
 */
CAS3Strategy.prototype.authenticate = function (req, options) {
  options = options || {}

  // CAS Logout flow as described in
  // https://wiki.jasig.org/display/CAS/Proposal%3A+Front-Channel+Single+Sign-Out var relayState = req.query.RelayState;
  const relayState = req.query.RelayState
  if (relayState) {
    // logout locally
    req.logout()
    return this.redirect(`${this.casServerURL}/logout?_eventId=next&RelayState=${relayState}`)
  }

  const service = this.service(req)
  const ticket = req.query.ticket

  if (!ticket) {
    const params = {
      service: this.service(req)
    }

    // copy loginParams in login query
    for (const property in options.loginParams) {
      const loginParam = options.loginParams[property]
      if (loginParam) {
        params[property] = loginParam
      }
    }

    const search = new URLSearchParams(params)

    const redirectURL = new URL(`${this.casServerURL}/login`)
    redirectURL.search = search

    this.redirect(redirectURL.href)
    return
  }

  const self = this
  const verified = function (err, user, info) {
    if (err) {
      self.error(err)
      return
    }

    if (!user) {
      self.fail(info)
      return
    }

    self.success(user, info)
  }

  const _validateUri = this.validateURL || this._validateUri

  const _handleResponse = function (response) {
    response.setEncoding('utf8')

    let body = ''
    response.on('data', (chunk) => {
      body += chunk
    })

    return response.on('end', function () {
      return self._validate(self, req, body, verified)
    })
  }

  const search = new URLSearchParams({
    ticket,
    service
  })

  const casUrl = this.parsed.href
  const reqUrl = new URL(`${casUrl}/${_validateUri}`)
  reqUrl.search = search

  // console.log('PARSED', this.parsed, reqUrl.href)

  const get = this.client.get(reqUrl.href, _handleResponse)

  get.on('error', function (e) {
    return self.fail(new Error(e))
  })
}

/**
 *
 * @param {*} req
 * @returns
 */
CAS3Strategy.prototype.service = function (req) {
  const serviceURL = this.serviceURL || req.originalUrl
  const resolvedURL = new URL(`${this.serverBaseURL}`) // /${serviceURL}`)
  // const resolvedURL = url.resolve(this.serverBaseURL, serviceURL)
  // const parsedURL = url.parse(resolvedURL, true)
  // delete parsedURL.query.ticket
  // delete parsedURL.search

  // console.log('URL', serviceURL, resolvedURL, this.serviceURL, this.serverBaseURL)

  return resolvedURL.href
}

module.exports = CAS3Strategy

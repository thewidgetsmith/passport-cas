/**
 * Cas
 */
const http = require('http')
const https = require('https')
const url = require('url')
const util = require('util')

const parseString = require('xml2js').parseString
const processors = require('xml2js/lib/processors')
const passport = require('passport')
const { v4: uuid } = require('uuid')

function Strategy (options, verify) {
  if (typeof options === 'function') {
    verify = options
    options = {}
  }
  if (!verify) {
    throw new Error('cas authentication strategy requires a verify function')
  }
  this.version = options.version || 'CAS1.0'
  this.ssoBase = options.ssoBaseURL
  this.serverBaseURL = options.serverBaseURL
  this.validateURL = options.validateURL
  this.serviceURL = options.serviceURL
  this.useSaml = options.useSaml || false
  this.parsed = url.parse(this.ssoBase)
  if (this.parsed.protocol === 'http:') {
    this.client = http
  } else {
    this.client = https
  }

  passport.Strategy.call(this)

  this.name = 'cas'
  this._verify = verify
  this._passReqToCallback = options.passReqToCallback

  const xmlParseOpts = {
    trim: true,
    normalize: true,
    explicitArray: false,
    tagNameProcessors: [processors.normalize, processors.stripPrefix]
  }

  const self = this
  switch (this.version) {
    case 'CAS1.0':
      this._validateUri = '/validate'
      this._validate = function (req, body, verified) {
        const lines = body.split('\n')
        if (lines.length >= 1) {
          if (lines[0] === 'no') {
            return verified(new Error('Authentication failed'))
          } else if (lines[0] === 'yes' && lines.length >= 2) {
            if (self._passReqToCallback) {
              self._verify(req, lines[1], verified)
            } else {
              self._verify(lines[1], verified)
            }
            return
          }
        }
        return verified(new Error('The response from the server was bad'))
      }
      break

    case 'CAS3.0':
      if (this.useSaml) {
        this._validateUri = '/samlValidate'
        this._validate = function (req, body, verified) {
          parseString(body, xmlParseOpts, function (err, result) {
            if (err) {
              return verified(new Error('The response from the server was bad'))
            }
            try {
              const response = result.envelope.body.response
              const success = response.status.statuscode.$.Value.match(/Success$/)
              if (success) {
                const attributes = {}
                for (const attr in response.assertion.attributestatement.attribute) {
                  attributes[attr.$.AttributeName.toLowerCase()] = attr.attributevalue
                }

                const profile = {
                  user: response.assertion.authenticationstatement.subject.nameidentifier,
                  attributes: attributes
                }

                if (self._passReqToCallback) {
                  self._verify(req, profile, verified)
                } else {
                  self._verify(profile, verified)
                }
                return
              }
              return verified(new Error('Authentication failed'))
            } catch (e) {
              return verified(new Error('Authentication failed'))
            }
          })
        }
      } else {
        this._validateUri = '/p3/serviceValidate'
        this._validate = function (req, body, verified) {
          parseString(body, xmlParseOpts, function (err, result) {
            if (err) {
              return verified(new Error('The response from the server was bad'))
            }
            try {
              if (result.serviceresponse.authenticationfailure) {
                return verified(new Error('Authentication failed ' + result.serviceresponse.authenticationfailure.$.code))
              }

              const success = result.serviceresponse.authenticationsuccess
              if (success) {
                if (self._passReqToCallback) {
                  self._verify(req, success, verified)
                } else {
                  self._verify(success, verified)
                }
                return
              }
              return verified(new Error('Authentication failed'))
            } catch (e) {
              return verified(new Error('Authentication failed'))
            }
          })
        }
      }
      break

    default:
      throw new Error('unsupported version ' + this.version)
  }
}

Strategy.prototype.service = function (req) {
  const serviceURL = this.serviceURL || req.originalUrl
  const resolvedURL = url.resolve(this.serverBaseURL, serviceURL)
  const parsedURL = url.parse(resolvedURL, true)
  delete parsedURL.query.ticket
  delete parsedURL.search
  return url.format(parsedURL)
}

Strategy.prototype.authenticate = function (req, options) {
  options = options || {}

  // CAS Logout flow as described in
  // https://wiki.jasig.org/display/CAS/Proposal%3A+Front-Channel+Single+Sign-Out var relayState = req.query.RelayState;
  const relayState = req.query.RelayState
  if (relayState) {
    // logout locally
    req.logout()
    return this.redirect(`${this.ssoBase}/logout?_eventId=next&RelayState=${relayState}`)
  }

  const service = this.service(req)
  const ticket = req.param('ticket')
  if (!ticket) {
    const redirectURL = url.parse(this.ssoBase + '/login', true)

    redirectURL.query.service = service
    // copy loginParams in login query
    for (const property in options.loginParams) {
      const loginParam = options.loginParams[property]
      if (loginParam) {
        redirectURL.query[property] = loginParam
      }
    }
    return this.redirect(url.format(redirectURL))
  }

  const self = this
  const verified = function (err, user, info) {
    if (err) {
      return self.error(err)
    }
    if (!user) {
      return self.fail(info)
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
      return self._validate(req, body, verified)
    })
  }

  if (this.useSaml) {
    const requestId = uuid()
    const issueInstant = new Date().toISOString()
    const soapEnvelope = util.format(
      `
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
          <SOAP-ENV:Header/>
          <SOAP-ENV:Body>
            <samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s">
              <samlp:AssertionArtifact>%s</samlp:AssertionArtifact>
            </samlp:Request>
          </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
      `,
      requestId,
      issueInstant,
      ticket
    )

    const request = this.client.request({
      host: this.parsed.hostname,
      port: this.parsed.port,
      method: 'POST',
      path: url.format({
        pathname: this.parsed.pathname + _validateUri,
        query: {
          TARGET: service
        }
      })
    }, _handleResponse)

    request.on('error', function (e) {
      return self.fail(new Error(e))
    })
    request.write(soapEnvelope)
    request.end()
  } else {
    const get = this.client.get({
      host: this.parsed.hostname,
      port: this.parsed.port,
      path: url.format({
        pathname: this.parsed.pathname + _validateUri,
        query: {
          ticket: ticket,
          service: service
        }
      })
    }, _handleResponse)

    get.on('error', function (e) {
      return self.fail(new Error(e))
    })
  }
}

exports.Strategy = Strategy

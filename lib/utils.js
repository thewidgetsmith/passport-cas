/**
 * Module dependencies
 */

const crypto = require('crypto')

/**
 * 62 characters in the ascii range that can be used in URLs without special
 * encoding.
 */
const UID_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

// EXPORTS

/**
 * Generate an Unique Id
 *
 * @param {Number} length  The number of chars of the uid
 * @returns {Promise<String>}
 */
exports.getSafeUserSessionID = async (length) => {
  const bytes = crypto.pseudoRandomBytes(length)

  let r = []
  for (let i = 0; i < bytes.length; i++) {
    r.push(UID_CHARSET[bytes[i] % UID_CHARSET.length])
  }

  return r.join('')
}

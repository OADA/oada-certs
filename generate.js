/*
 generate returns an encrypted JWT that represents the signed data.

 The result looks like this:
   dffji2ds.2f2309ijf234kf2l.2f823jhio
 that's just a random string, but in practice is a real JWT.

 "key" can either be an object with a "pem" key, or a jwk that can be converted to a pem.
 If the signing key has a kid (i.e. a "key id"), it will be added to the resulting JWT headers

 If there is no "options.header.jku" or no "options.header.kid", then we will put the public
 JWK into the JWT header directly.  If they are there, we will just put the jku and kid in there
 directly but not the public jwk.

*/

const jwt = require('jsonwebtoken');
const pemjwk = require('pem-jwk');
//const skeemas = require('skeemas');
//const clientcertSchema= require('./schemas/clientcert.json');
const errors = require('./errors');
const debug = require('debug');
const  info = debug('oada-certs:info');
const trace = debug('oada-certs:trace');

function generate(payload, key, options) {
  options = options || { };
  if (!key) throw new errors.InvalidKeyException("You have to pass a valid JWK or an object with a pem key as the signing key");
  // You can pass the pem in the key itself, or you can pass a JWK as the key:
  const pem = key.pem || pemjwk.jwk2pem(key);
  const privatejwk = pemjwk.pem2jwk(pem);
  // Public only keeps kty, n, and e.  If kid is there, keep the key id too
  const publicjwk = {
    kty: privatejwk.kty,
    n: privatejwk.n,
    e: privatejwk.e,
  };
  if (privatejwk.kid) publicjwk.kid = privatejwk.kid;
  
  options = options || {};
  options.header = options.header || {};
  options.header.typ = options.header.typ || 'JWT';
  options.header.alg = options.header.alg || 'RS256';

  // If there is a kid on the key ("key id"), it will be kept in the JWT
  if (key.kid) {
    trace('key has a kid (',key.kid,'), putting in header');
    options.header.kid = key.kid;
  }

  // If there is a jku and kid in options.header, then don't put the public JWK 
  // in there that we are using to sign.  If either is missing, then we need to
  // put the JWK in there or it can't be validated later because the public key
  // is not find-able.
  if (!options.header.jku || !options.header.kid) {
    options.header.jwk = publicjwk;
  }

  /* I am removing this schema test because this library should be capable of signing
   * anything, not just an OADA client certificate.  For example, Trellis uses it to 
   * sign a hash of arbitrary data.
   * const result = skeemas.validate(payload, clientcertSchema);
   * if (!result.valid) {
   *   throw new errors.InvalidFormatException(
   *     'Unsigned payload does not match valid schema.  Cert was: '+JSON.stringify(payload, false, '  '),
   *     result.errors
   *   );
   * }
  */

  try {
    return jwt.sign(payload, pem, options);
  } catch(e) {
    trace('Failed to sign payload, error was: ', e, ', payload = ', payload, ', pem = ', pem, ', options = ', options);
    throw new errors.SignatureFailedException('Unable to sign certificate with jsonwebtoken.sign()', [ e ]);
  }
}

module.exports = generate;

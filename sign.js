/*
 sign returns an encrypted JWT that represents the signed data.

 The result looks like this:
   dffji2ds.2f2309ijf234kf2l.2f823jhio
 that's just a random string, but in practice is a real JWT.

 "key" can either be an object with a "pem" key, or a jwk that can be converted to a pem.
 If the signing key has a kid (i.e. a "key id"), it will be added to the resulting JWT headers

 If there is no "options.header.jku" or no "options.header.kid", then we will put the public
 JWK into the JWT header directly.  If they are there, we will just put the jku and kid in there
 directly but not the public jwk.

*/

const _ = require('lodash');
const jose = require('node-jose');
const errors = require('./errors');
const debug = require('debug');
const  info = debug('oada-certs:info');
const trace = debug('oada-certs:trace');

async function sign(payload, key, options) {
  options = options || { };
  if (!key) throw new errors.InvalidKeyException("You have to pass a valid JWK or an object with a pem key as the signing key");
  // You can pass the pem in the key itself, or you can pass a JWK as the key:
  if (typeof key === 'string') {
    key = { pem : key }; // passed the key as a regular pem string instead of object like a jwk
  }
  // asKey needs the key to be just the pem string if it's a pem 
  let privatejwk = null;
  if (key.pem) {
    privatejwk = await jose.JWK.asKey(key.pem, 'pem');
  } else { // regular JWK:
    privatejwk = await jose.JWK.asKey(key);
  }
  //if (key.kid) privatejwk.kid = key.kid; // maintain kid from original if passed
  // options.header.kid can override the one in the private key:
  if (options.header && options.header.kid) {
    trace('sign: Setting kid in private key to options.header.kid value of ', options.header.kid);
    const json = privatejwk.toJSON(true);
    json.kid = options.header.kid;
    privatejwk = await jose.JWK.asKey(json);
  }
  trace('sign: kid on privatejwk = ', privatejwk.kid);

  // Public only keeps kty, n, and e.  If kid is there, keep the key id too
  const publicjwk = privatejwk.toJSON(); // without a parameter, this returns the public key
  if (privatejwk.kid) publicjwk.kid = privatejwk.kid;
  
  options = options || {};
  options.header = options.header || {};
  options.header.typ = options.header.typ || 'JWT';
  options.header.alg = options.header.alg || 'RS256';

  // If there is a kid on the key ("key id"), it will be kept in the JWT
  if (privatejwk.kid) {
    trace('key has a kid (',privatejwk.kid,'), putting in header');
    options.header.kid = privatejwk.kid;
  }

  // There is some wonkiness when the payload is just a regular string.  It seems
  // that the sign functions expect a string to be able to JSON.parse, so a simple
  // string variable breaks that.  We'll do a quick test and if it parses, we'll
  // use it.  If it doesn't, we'll JSON.stringify() it (which will surround it in quotes)
  if (typeof payload === 'string') {
    try {
      JSON.parse(payload);
    } catch(err) {
      payload = JSON.stringify(payload);
    }
  }
  // The sign function will only sign strings, so if we have an object, we have to stringify it
  if (typeof payload === 'object') {
    payload = JSON.stringify(payload);
  }

  // We need to save the jwk in the header so that it can be validated even if the trusted list
  // is not available.  i.e. you should put
  // options.header.jku = "<URL to your key set>"
  // options.header.kid = "<id of this JWK in that key set>"
  // in options, and that will inform the trust check, but will will also include the JWK used
  // here in the header so that the JWT can be verified directly without performing the external trust check.
  // You should ALWAYS use the one at the jku URL when available rather than the one on the header.
  options.header.jwk = _.cloneDeep(publicjwk);

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
    return await jose.JWS.createSign({format: 'compact'},{ key: privatejwk, header: options.header }).update(payload).final();
  } catch(e) {
    trace('Failed to sign payload, error was: ', e, ', payload = ', payload, ', key = ', key, ', options = ', options);
    throw new errors.SignatureFailedException('Unable to sign certificate with jose.JWS.createSign().update().final()', [ e ]);
  }
}

module.exports = sign;

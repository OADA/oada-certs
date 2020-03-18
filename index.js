module.exports = {
  // Sign a client certificate:
  sign: require('./sign'),
  // Validate a client certificate (also check trusted):
  validate: require('./validate'),
  // Handy JWK utilities like jwkForSignature and decodeWithoutVerify
  jwksutils: require('./jwks-utils'),
  // Wrapper for node-jose to create an RSA public/private keypair for you (2048 bit key length)
  keys: require('./keys'),
  // Expose the underlying crypto library in case somebody finds that handy upstream
  jose: require('node-jose'),
}

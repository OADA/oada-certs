module.exports = {
  // Sign a client certificate:
  sign: require('./sign'),
  // Validate a client certificate (also check trusted):
  validate: require('./validate'),
  // Handy JWK utilities like jwkForSignature and decodeWithoutVerify
  jwksutils: require('./jwks-utils'),
  // Wrapper for node-jose to create an RSA public/private keypair for you (2048 bit key length)
  createKey: require('./createKey'),
}

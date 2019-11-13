module.exports = {
  // Sign a client certificate:
  generate: require('./generate'),
  // Validate a client certificate (also check trusted):
  validate: require('./validate'),
  // Handy JWK utilities like jwkForSignature
  jwksutils: require('./jwks-utils'),
}

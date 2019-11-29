# oada-certs #

Use this to create/sign/interact with OADA developer certificates.

## Installation ##
```shell
# If you want command-line tool:
npm install -g @oada/oada-certs

# If you just want to use the JS libs in your project:
npm install @oada/oada-certs
```

## Command-line: setup an OADA domain folder ##
```shell
cd domain_folder
oada-certs --create-keys
oada-certs
```
NOTE: default is to look in the current folder for signing keys

## Command-line: sign a certificate ##
```shell
# creates signed_software_statement.js in current folder
oada-certs --signkey="./some_path_to_privatekey_pem" --sign=./some_path_to_unsigned_cert.js

# If you are hosting signing key with a jku:
oada-certs --signkey="./some_path_to_privatekey_pem" --signjku="https://some.jku.url" --signkid="someKeyIdAtThatJKU" --sign="./path_to_unsigned_cert.js"
```

## Command-line: validate/debug a certificate
```shell
# Note: caching is in-memory and therefore unused here
oada-certs --validate="signed_software_statement.js"

# If there are errors, they will print here.  It will
# also tell you if the certificate is trusted
```

## Include library in javascript: ##
```javascript
const oadacerts = require('@oada/oada-certs');

// If you don't pass a jku, it puts the public jwk for the
// sign key into the JWT automatically
try {
  const signed_jwt_cert = oadacerts.generate(clientcert, signkey, { 
    jku: "https://url.to.some.jwkset", 
    kid: "someKeyidInThatSet"
  });
} catch(err) {
  console.log('Error in signing certificate');
}

// Returns a promise:
const { trusted, clientcert, valid, details } = await oadacerts.validate(signed_jwt_cert);
// trusted = true if cert was signed by key on a trusted list
// clientcert = JSON object that is the decoded client certicate
// valid = true if cert was decodable with a correct signature
// details = array of details about the validation process to help with debugging a cert
// NOTE: if the certificate is untrusted, it cannot use a jku in the signature, 
//    it must use a jwk to be considered valid.  This avoids fetching potentially malicious URL's.

// Self-explanatory utilities for working with JWK key sets (jwks):
oadacerts.jwksutils.isJWK(key)
oadacerts.jwksutils.isJWKset(set)
oadacerts.jwksutils.findJWK(kid, jwks)
// jwkForSignature attempts to figure out the correct public JWK to use in
// validating a given signature.  Uses an intelligent cache for remote-hosted
// jwk's.  
// What makes this function tricky is the "hint":
// It was designed to make it simple to say something like:
// "hint: I looked up the JKU ot JWK on the signature, and it was from a trusted source." 
// (i.e. hint = truthy), 
// and it's truthy value is then either the JWKS (object) from the trusted source, 
//     or the jku (string) of the trusted source's jwks
// or 
// "hint: I looked at my trusted sources and this one doesn't have a jwk or jku that matches." 
// (i.e. hint === false)
// which means "just use the header on the signature because I have no outside reference that verifies it"
//
// - If boolean false, use the jku from the jose header and if no jku then use jose's jwk
// - If boolean true, throw error (it should have been either an object or a string)
// - If string, assume string is a jku uri, go get that URI and then check jose's jwk against it
// - If object and looks like a jwks, look for jose's jwk in the set
// - If object and looks like a jwk, compare that jwk with jose's jwk
const jwk = oadacerts.jwksutils.jwkForSignature(jwt, hint, { timeout: 1000 })
```



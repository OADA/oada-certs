#! /usr/bin/env node

const inquirer = require('inquirer');
const minimist = require('minimist');
const uuid = require('uuid/v4');
const pemjwk = require('pem-jwk');
const fs = require('fs');
const Promise = require('bluebird');
const fsp = Promise.promisifyAll(fs);
const execa = require('execa');
const argv = minimist(process.argv.slice(2));
const debug = require('debug');
const error = debug('oada-certs:error');
const trace = debug('oada-certs:trace');
const info = debug('oada-certs:info');

const oadacerts  = require('.');

//-----------------------------------------------------
// Most important note: if you are already in a folder
// with public_key.pem, private_key.pem, and public_key.jwk
// as well as an unsigned_software_statement.js file,
// (i.e. a domains-available folder), then you can just run this
// without arguments like:
// oada-certs


//----------------------------------------------------------------
// --validate
//----------------------------------------------------------------
if (argv.validate) {
  // If they passed a filename on --validate, go ahead and validate that 
  // instead of the default.  Otherwise, --validate was empty so use default:
  let signedcertpath = './signed_software_statement.js';
  if (argv.validate && argv.validate.length > 0 && !fs.existsSync(argv.validate)) {
    signedcertpath = argv.validate;
  }
  // the signedcert may be a javascript file that is module.exports = "stringcert",
  // or just the string cert itself.  eval it if it's the module.exports.
  let signedcert = fs.readFileSync(signedcertpath).toString();
  if (signedcert.match(/module\.exports/)) {
    signedcert = eval(signedcert);
  } else {
    // Or, it's a JSON file: try to parse and if failure, must be the raw JWT
    try { signedcert = JSON.parse(signedcert); } 
    catch(e) { }
  }
  // Now validate the JWT:
  return oadacerts.validate(signedcert)
  .then(({clientcert,trusted,valid,details}) => {
    console.log('trusted: ', trusted);
    console.log('valid: ', valid);
    console.log('decoded client cert: ', clientcert);
    console.log('details on validation: ', details);
  });
}

//------------------------------------------------------
// oada-certs --create-keys
// oada-certs --create-keys --force # CAREFUL THIS DELETES PRIVATE KEY!
// Use #1: create a private/public signing keypair for signing future oauth2 requests from this certificate:
//   creates ./public_key.pem
//           ./private_key.pem
//           ./public_key.jwk
//   --force-creation will remove pre-existing key files
if (argv["create-keys"]) {
  if(argv.force) {
    console.log('You asked for --force, removing key files');
    try {
      fs.unlinkSync('./private_key.pem');
      fs.unlinkSync('./public_key.pem');
      fs.unlinkSync('./public_key.jwk');
    } catch(e) {
      // don't care if some of them didn't exist
    }
  }

  console.log('Creating keys ./private_key.pem and ./public_key.pem...');
  if (fs.existsSync('./private_key.pem')) {
    throw new Error('ERROR: ./private_key.pem already exists, refusing to overwrite.  force with --force-creation');
  }
  if (fs.existsSync('./public_key.pem')) {
    throw new Error('ERROR: ./public_key.pem already exists, refusing to overwrite.  force with --force-creation');
  }
  if (fs.existsSync('./public_key.jwk')) {
    throw new Error('ERROR: ./public_key.jwk already exists, refusing to overwrite.  force with --force-creation');
  }
  console.log('openssl genrsa -out private_key.pem 2048');
  return execa('openssl', ['genrsa', '-out', 'private_key.pem', '2048'])
  .then(result => {
    console.log('Private key created.  openssl said: ', result.stdout);
    console.log('Extracting public key...');
    return execa('openssl', ['rsa', '-pubout', '-in', 'private_key.pem', '-out', 'public_key.pem']);
  }).then(result => {
    console.log('Done extracting public key.  openssl said: ', result.stdout);
    console.log('Creating jwk from public key');
    const pubkeypem = fs.readFileSync('./public_key.pem').toString();
    const jwk = pemjwk.pem2jwk(pubkeypem);
    // assign the jwk a random keyid (kid):
    jwk.kid = uuid().replace(/-/g,''); // get rid of the dashes
    fs.writeFileSync('./public_key.jwk', JSON.stringify(jwk));
    console.log('Done creating ./public_key.jwk');
    console.log('IMPORTANT: for now, you have to put this jwk into your unsigned_clientcert.js manually as your signing key for OAuth2 requests');
  });
  // done here.
}

//-----------------------------------------------------------
// oada-certs --sign=unsigned_software_statement.js
//
// Use #2: signing an unsigned client developer certificate
// to turn it into a JWT:
// oada-certs --signkey=./signing_private_key.pem \
//            --sign unsigned_clientcert.js
// This first version will put the public jwk key into the header of the JWT
// directly in the certificate.
//
// OR
//
// oada-certs --signkey=./signing_private_key.pem \
//            --signjku=https://some.url.where.jwks.lives
//            --signkid=<a key id in that jwk set>
// This second version will put a jku and kid in the header of the JWT, and
// clients will have to lookup the kid in the set of jwk's at that jku.
//
// Get the key needed to sign the certificate as the registration provider:
const signkeypath = argv.signkey || (__dirname + '/test/dev_privatekey.pem');
const signkey = {
  pem: fs.readFileSync(signkeypath).toString(),
  kid: argv.signkid || 'dev1',
};

// Read the unsigned client certificate path on --sign
const unsignedcertpath = argv.sign || './unsigned_software_statement.js';
let unsignedcert;
try {
  unsignedcert = eval(fs.readFileSync(unsignedcertpath).toString()); // have to eval intead of require for file paths to match
} catch(e) {
  error('Failed to read unsigned cert ',unsignedcertpath,'.  Error was: ', e);
  throw e;
}

// Check which kind of public key storage they want: 
//   option 1: public key is hosted in a jwk set at a URL.  
//             pass --signjku=<the_url>, and --signkid=<the_kid> 
//             for which key in the set
//   option 2: public key is to be included in the signature itself.  Do not pass a jku,
//             and the public jwk will be added to the resulting JWT header automatically.
const options = {};
if (argv.signjku) options.header.jku = argv.signjku;
if (argv.signkid) options.header.kid = argv.signkid;


// Generate the signed version of the client cert:
const signedcert = oadacerts.generate(unsignedcert, signkey, options);

// Write to file:
fs.writeFileSync('./signed_software_statement.js', "module.exports = "+JSON.stringify(signedcert)+";");

console.log('Wrote JWT to ./signed_software_statement.js');



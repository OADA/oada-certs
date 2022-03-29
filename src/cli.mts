/**
 * @license
 * Copyright 2022 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* eslint-disable no-console */

import { readFile, unlink, writeFile } from 'node:fs/promises';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

import debug from 'debug';
import minimist from 'minimist';
import pemjwk from 'pem-jwk';

import { keys, sign, validate } from '.';
import type { JOSEHeader } from './jwks-utils';

const argv = minimist(process.argv.slice(2));
const error = debug('oada-certs:error');

// -----------------------------------------------------
// Most important note: if you are already in a folder
// with public_key.pem, private_key.pem, and public_key.jwk
// as well as an unsigned_software_statement.js file,
// (i.e. a domains-available folder), then you can just run this
// without arguments like:
// oada-certs

// ----------------------------------------------------------------
// --validate
// ----------------------------------------------------------------
if (argv.validate) {
  // If they passed a filename on --validate, go ahead and validate that
  // instead of the default.  Otherwise, --validate was empty so use default:
  let signedcertpath = './signed_software_statement.js';
  if (
    argv.validate &&
    argv.validate.length > 0 &&
    !fs.existsSync(argv.validate)
  ) {
    signedcertpath = argv.validate as string;
  }

  // The signedcert may be a javascript file that is module.exports = "stringcert",
  // or just the string cert itself.  eval it if it's the module.exports.
  let signedcert = (await readFile(signedcertpath)).toString();
  if (signedcert.includes('module.exports')) {
    signedcert = eval(signedcert) as string;
  } else {
    // Or, it's a JSON file: try to parse and if failure, must be the raw JWT
    try {
      signedcert = JSON.parse(signedcert) as string;
    } catch {}
  }

  // Now validate the JWT:
  const { payload, trusted, valid, details } = await validate.validate(
    signedcert
  );
  console.log('trusted:', trusted);
  console.log('valid:', valid);
  console.log('decoded payload:', payload);
  console.log('details on validation:', details);
}

// ------------------------------------------------------
// oada-certs --create-keys
// oada-certs --create-keys --force # CAREFUL THIS DELETES PRIVATE KEY!
// Use #1: create a private/public signing keypair for signing future oauth2 requests from this certificate:
//   creates ./public_key.pem
//           ./private_key.pem
//           ./public_key.jwk
//   --force will remove pre-existing key files
if (argv['create-keys']) {
  if (argv.force) {
    console.log('You asked for --force, removing key files');
    try {
      await unlink('./private_key.pem');
      await unlink('./public_key.pem');
      await unlink('./public_key.jwk');
    } catch {
      // Don't care if some of them didn't exist
    }
  }

  console.log('Creating keys ./private_key.pem and ./public_key.pem...');
  if (fs.existsSync('./private_key.pem')) {
    throw new Error(
      'ERROR: ./private_key.pem already exists, refusing to overwrite.  force with --force'
    );
  }

  if (fs.existsSync('./private_key.jwk')) {
    throw new Error(
      'ERROR: ./private_key.jwk already exists, refusing to overwrite.  force with --force'
    );
  }

  if (fs.existsSync('./public_key.pem')) {
    throw new Error(
      'ERROR: ./public_key.pem already exists, refusing to overwrite.  force with --force'
    );
  }

  if (fs.existsSync('./public_key.jwk')) {
    throw new Error(
      'ERROR: ./public_key.jwk already exists, refusing to overwrite.  force with --force'
    );
  }

  console.log(
    'You could use "openssl genrsa -out private_key.pem 2048" to sign keys, but this will use built-in library'
  );
  const result = await keys.create();
  console.log('Keys created, converting to PEM and writing output');
  await Promise.all([
    writeFile('./public_key.pem', pemjwk.jwk2pem(result.public)),
    writeFile('./public_key.jwk', JSON.stringify(result.public)),
    writeFile('./private_key.pem', pemjwk.jwk2pem(result.private)),
    writeFile('./private_key.jwk', JSON.stringify(result.private)),
  ]);
  console.log(
    'Done creating ./public_key.pem, ./private_key.pem, ./public_key.jwk, and ./private_key.jwk'
  );
  console.log(
    'IMPORTANT: for now, you have to put the jwk from ./public_key.jwk into your unsigned_clientcert.js manually as your signing key for OAuth2 requests'
  );
  // Done here.
}

// -----------------------------------------------------------
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
const signkeypath =
  (argv.signkey as string) ||
  `${path.dirname(url.fileURLToPath(import.meta.url))}/test/dev_privatekey.pem`;
const file = await readFile(signkeypath);
const signkey = {
  pem: file.toString(),
  kid: (argv.signkid as string) || 'dev1',
};

// Read the unsigned client certificate path on --sign
const unsignedcertpath =
  (argv.sign as string) || './unsigned_software_statement.js';
let unsignedcert;
try {
  const cert = await readFile(unsignedcertpath);
  unsignedcert = eval(cert.toString()) as string; // Have to eval instead of require for file paths to match
} catch (error_: unknown) {
  error(
    'Failed to read unsigned cert ',
    unsignedcertpath,
    '.  Error was: ',
    error_
  );
  throw error_;
}

// Check which kind of public key storage they want:
//   option 1: public key is hosted in a jwk set at a URL.
//             pass --signjku=<the_url>, and --signkid=<the_kid>
//             for which key in the set
//   option 2: public key is to be included in the signature itself.  Do not pass a jku,
//             and the public jwk will be added to the resulting JWT header automatically.
const options: { header: Partial<JOSEHeader> } = { header: {} };
if (argv.signjku) {
  options.header.jku = argv.signjku as string;
}

if (argv.signkid) {
  options.header.kid = argv.signkid as string;
}

// Generate the signed version of the client cert:
const signedcert = await sign(unsignedcert, signkey, options);

// Write to file:
await writeFile(
  './signed_software_statement.js',
  `module.exports = ${JSON.stringify(signedcert)};`
);

console.log('Wrote JWT to ./signed_software_statement.js');
